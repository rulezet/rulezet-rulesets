rule CheckPlease {
  meta:
    description   = "Detection patterns for the tool 'CheckPlease' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "CheckPlease"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /check_all.*\.c/ nocase ascii wide
            $string2 = /check_all.*\.go/ nocase ascii wide
            $string3 = /check_all.*\.pl/ nocase ascii wide
            $string4 = /check_all.*\.ps1/ nocase ascii wide
            $string5 = /check_all.*\.py/ nocase ascii wide
            $string6 = /CheckPlease/ nocase ascii wide

  condition:
    any of them
}