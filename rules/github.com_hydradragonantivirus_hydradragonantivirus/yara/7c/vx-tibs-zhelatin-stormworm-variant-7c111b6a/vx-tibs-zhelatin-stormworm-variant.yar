import "pe"
rule VX__Tibs_Zhelatin__StormWorm__variant {
  strings:
    $a0 = { FF 74 24 1C 58 8D 80 ?? ?? 77 04 50 68 62 34 35 04 E8 }

  condition:
    $a0 at pe.entry_point
}