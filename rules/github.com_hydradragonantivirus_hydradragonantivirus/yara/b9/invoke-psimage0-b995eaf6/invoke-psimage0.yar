rule Invoke_PSImage0 {
  meta:
    description   = "Detection patterns for the tool 'Invoke-PSImage' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "Invoke-PSImage"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /Invoke\-PSImage/ nocase ascii wide

  condition:
    any of them
}