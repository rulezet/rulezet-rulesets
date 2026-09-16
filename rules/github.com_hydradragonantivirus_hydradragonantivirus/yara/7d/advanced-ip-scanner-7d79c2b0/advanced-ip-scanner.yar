rule advanced_ip_scanner_ {
  meta:
    description   = "Detection patterns for the tool 'advanced-ip-scanner' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "advanced-ip-scanner"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1 = /Advanced\sIP\sScanner/ nocase ascii wide
            $string2 = /advanced_ip_scanner/ nocase ascii wide
            $string3 = /Advanced_IP_Scanner.*\.exe/ nocase ascii wide
            $string4 = /https:\/\/download\.advanced\-ip\-scanner\.com\/download\/files\/.*\.exe/ nocase ascii wide

  condition:
    any of them
}