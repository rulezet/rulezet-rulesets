rule FMFASweep {
  meta:
    description   = "Detection patterns for the tool 'FMFASweep' taken from the ThreatHunting-Keywords github project"
    author        = "@mthcht"
    reference     = "https://github.com/mthcht/ThreatHunting-Keywords"
    tool          = "FMFASweep"
    rule_category = "offensive_tool_keyword"

  strings:
            $string1 = /\/MFASweep\.git/ nocase ascii wide
            $string2 = /dafthack\/MFASweep/ nocase ascii wide
            $string3 = /Invoke\-MFASweep/ nocase ascii wide
            $string4 = /MFASweep\.ps1/ nocase ascii wide

  condition:
    any of them
}