rule PowerOPS {
  meta:
    description   = "Detection patterns for the tool 'PowerOPS' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "PowerOPS"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /PowerOPS/ nocase ascii wide

  condition:
    any of them
}