rule amass {
  meta:
    description   = "Detection patterns for the tool 'amass' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "amass"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /OWASP.*Amass/ nocase ascii wide

  condition:
    any of them
}