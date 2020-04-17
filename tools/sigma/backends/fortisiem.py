# Output backends for sigmac
# Copyright 2019-2020 Chris Durkin, Thomas Patzke

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin

class FortiSIEMQueryBackend(SingleTextQueryBackend):
    """Converts Sigma rule into FortiSIEM query."""
    identifier = "fortisiem-query"
    active = True

    logsource_mappings = {      # (category, product, service) -> (eventType value, match mode)
                                # eventType value with placeholder {} for event ID
                                # match mode = exact (True) or contains (False) match
                                # None in key = don't care
                (None, "windows", "security"): ("Win-Security-{}", True),
                (None, "windows", "sysmon"): ("Win-Sysmon-{}", False),
            }

    reEscape = re.compile('("|(?<!\\\\)\\\\(?![*?\\\\]))')
    reClear = None
    andToken = " AND "
    orToken = " OR "
    notToken = "NOT "
    subExpression = "%s"
    listExpression = "(%s)"
    listSeparator = ","
    valueExpression = "\"%s\""
    nullExpression = "NOT %s=\"*\""
    notNullExpression = "%s=\"*\""
    mapExpression = "%s=%s"
    mapListsSpecialHandling = True
    mapListValueExpression = "%s IN %s"

    def generateMapItemListNode(self, key, value):
        if not set([type(val) for val in value]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        if key == "winEventId":
            self.eventids.extend(value)
        return key + " IN (" + (", ".join([self.generateValueNode(item) for item in value])) + ")"

    def generateMapItemNode(self, node):
        """
        FortiSIEM has an event type field that contains the log source as well as the Events EventID.
        """
        key, val = node
        if key == "winEventId" and type(val) in (str, int):
            self.eventids.append(val)
        return super().generateMapItemNode(node)

    def match_logsource(self, logsource):
        """Matches log source definition from sigma rule against logosurce_mappings. Returns matched item from mappings."""
        for k, v in self.logsource_mappings.items():    # iterate through all log source definitions from above
            match_vector = [    # all sub conditons must match
                    k[i] is None or (getattr(logsource, c) is not None and k[i] == getattr(logsource, c))  # log source element from mapping is empty or must match real log source
                    for c, i in zip(("category", "product", "service"), range(4))   # iterate over all log source items defined by Sigma specification
                ]
            if all(match_vector):
                return v

    def generate(self, sigmaparser):
        self.eventids = list()
        query = super().generate(sigmaparser)
        lsdef = self.match_logsource(sigmaparser.get_logsource())
        if lsdef is not None:
            val, exact = lsdef
            if len(self.eventids) > 0:
                lscond = " OR ".join([
                            "eventType " + ( "=" if exact else "CONTAIN" ) + ' "' +  val.format(eventid) + '"'
                            for eventid in self.eventids
                        ])
            else:
                lscond = 'eventType CONTAIN "' + val.format("") + '"'

            return lscond + " AND (" + query + ")"
        else:
            return query
