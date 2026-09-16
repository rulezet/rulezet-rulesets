rule PEiD_00344_Borland_Delphi_v5_0_KOL_ {
  meta:
    description = "[Borland Delphi v5.0 KOL]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}