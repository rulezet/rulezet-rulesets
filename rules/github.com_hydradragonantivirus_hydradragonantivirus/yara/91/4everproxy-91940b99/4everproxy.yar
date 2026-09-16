rule _4everproxy {
  meta:
    description   = "Detection patterns for the tool '4everproxy' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "4everproxy"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /vh\.4everproxy\.com\/secure\// nocase ascii wide
            $string2 = /www\.4everproxy\.com\/tor\-proxy/ nocase ascii wide

  condition:
    any of them
}