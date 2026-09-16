import "pe"
rule borland_delphi_6_7: Compiler {
  meta:
    author      = "Kevin Falcoz"
    date_create = "25/02/2013"
    description = "Borland Delphi 6.0 - 7.0"

  strings:
    $str1 = { 55 8B EC 83 C4 F0 53 B8 [3] 00 E8 [3] FF 8B 1D [3] 00 8B 03 BA [2] 52 00 E8 [2] F6 FF B8 [2] 52 00 E8 [2] FF FF 8B 03 E8 }  
    $str2 = { 55 8B EC B9 ?? 00 00 00 6A 00 6A 00 49 75 F9 [0-1] 53 [9-11] FF 33 C0 55 68 [3] 00 64 FF 30 64 89 20 }  

  condition:
    $str1 at (pe.entry_point) or $str2 at (pe.entry_point)
}