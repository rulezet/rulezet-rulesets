rule borland_delphi_5_kol {
  meta:
    author      = "PEiD"
    description = "Borland Delphi 5.0 KOL"
    group       = "444"
    function    = "0"

  strings:
    $a0 = { 55 8B EC 83 C4 F0 B8 ?? ?? 40 00 E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF 8B C0 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a0
}