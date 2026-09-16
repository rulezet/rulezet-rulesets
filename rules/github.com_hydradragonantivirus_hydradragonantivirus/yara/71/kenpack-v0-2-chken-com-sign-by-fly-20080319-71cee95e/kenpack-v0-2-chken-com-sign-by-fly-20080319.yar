import "pe"
rule KenPack_V0_2____CHKen_Com_____Sign_By_fly___20080319 {
  strings:
    $a0 = { 6A 18 E8 14 00 00 00 58 8D 4A 18 51 8D 92 ?? ?? ?? ?? 64 8B 08 FF 31 89 21 89 10 5A FF E2 72 8B 44 24 0C 8B ?? A8 00 00 00 8D 8A ?? ?? ?? ?? 60 }

  condition:
    $a0 at pe.entry_point
}