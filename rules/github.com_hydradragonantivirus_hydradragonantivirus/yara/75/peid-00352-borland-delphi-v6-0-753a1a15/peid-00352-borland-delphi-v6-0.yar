rule PEiD_00352_Borland_Delphi_v6_0_ {
  meta:
    description = "[Borland Delphi v6.0]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 ?? ?? 45 00 E8 ?? ?? ?? FF A1 ?? ?? 45 00 8B 00 E8 ?? ?? FF FF 8B 0D }

  condition:
    $a
}