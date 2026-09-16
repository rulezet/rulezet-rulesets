rule CACTUSTORCH0 {
  meta:
    description   = "Detection patterns for the tool 'CACTUSTORCH' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "CACTUSTORCH"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /CACTUSTORCH/ nocase ascii wide

  condition:
    any of them
}