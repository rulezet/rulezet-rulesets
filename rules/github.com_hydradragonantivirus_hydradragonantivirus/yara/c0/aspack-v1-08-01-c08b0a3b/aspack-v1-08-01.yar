import "pe"
rule ASPack_v1_08_01 {
  strings:
    $a0 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 ?? BB 10 ?? 44 ?? 03 DD 2B 9D }
    $a1 = { 60 EB ?? 5D EB ?? FF ?? ?? ?? ?? ?? E9 }
    $a2 = { 60 EB 0A 5D EB 02 FF 25 45 FF E5 E8 E9 E8 F1 FF FF FF E9 81 ?? ?? ?? 44 00 BB 10 ?? 44 00 03 DD 2B 9D }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}