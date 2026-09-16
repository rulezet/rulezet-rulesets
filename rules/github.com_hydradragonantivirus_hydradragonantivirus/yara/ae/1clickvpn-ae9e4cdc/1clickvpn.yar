rule _1clickVPN {
  meta:
    description   = "Detection patterns for the tool '1clickVPN' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "1clickVPN"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1 = /fcfhplploccackoneaefokcmbjfbkenj/ nocase ascii wide

  condition:
    any of them
}