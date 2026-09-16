rule PEiD_00347_Borland_Delphi_v6_0___v7_0_ {
  meta:
    description = "[Borland Delphi v6.0 - v7.0]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 ?? ?? ?? ?? E8 }

  condition:
    $a
}