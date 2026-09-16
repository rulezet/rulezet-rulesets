rule WMImplant0 {
  meta:
    description   = "Detection patterns for the tool 'WMImplant' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "WMImplant"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /WMImplant/ nocase ascii wide

  condition:
    any of them
}