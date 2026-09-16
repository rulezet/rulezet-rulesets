rule portscan0 {
  meta:
    description   = "Detection patterns for the tool 'portscan' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "portscan"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /portscan/ nocase ascii wide

  condition:
    any of them
}