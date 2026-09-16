rule _ {
  meta:
    description   = "Detection patterns for the tool '_' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "_"
    rule_category = "greyware_tool_keyword"

  strings:
            $string1  = /\/keygen\.exe/ nocase ascii wide
            $string2  = /\\1\.bat/ nocase ascii wide
            $string3  = /\\1\.dll/ nocase ascii wide
            $string4  = /\\1\.exe/ nocase ascii wide
            $string5  = /\\2\.bat/ nocase ascii wide
            $string6  = /\\2\.dll/ nocase ascii wide
            $string7  = /\\2\.exe/ nocase ascii wide
            $string8  = /\\3\.bat/ nocase ascii wide
            $string9  = /\\3\.dll/ nocase ascii wide
            $string10 = /\\3\.exe/ nocase ascii wide
            $string11 = /\\4\.bat/ nocase ascii wide
            $string12 = /\\4\.dll/ nocase ascii wide
            $string13 = /\\4\.exe/ nocase ascii wide
            $string14 = /\\5\.bat/ nocase ascii wide
            $string15 = /\\5\.dll/ nocase ascii wide
            $string16 = /\\5\.exe/ nocase ascii wide
            $string17 = /\\6\.bat/ nocase ascii wide
            $string18 = /\\6\.dll/ nocase ascii wide
            $string19 = /\\6\.exe/ nocase ascii wide
            $string20 = /\\7\.bat/ nocase ascii wide
            $string21 = /\\7\.dll/ nocase ascii wide
            $string22 = /\\7\.exe/ nocase ascii wide
            $string23 = /\\8\.bat/ nocase ascii wide
            $string24 = /\\8\.dll/ nocase ascii wide
            $string25 = /\\8\.exe/ nocase ascii wide
            $string26 = /\\9\.bat/ nocase ascii wide
            $string27 = /\\9\.dll/ nocase ascii wide
            $string28 = /\\9\.exe/ nocase ascii wide
            $string29 = /\\keygen\.exe/ nocase ascii wide

  condition:
    any of them
}