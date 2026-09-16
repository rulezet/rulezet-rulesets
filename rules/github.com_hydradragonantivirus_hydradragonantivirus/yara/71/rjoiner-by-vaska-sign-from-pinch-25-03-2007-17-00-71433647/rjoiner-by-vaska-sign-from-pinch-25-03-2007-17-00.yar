import "pe"
rule RJoiner_by_Vaska__Sign_from_pinch_25_03_2007_17_00_ {
  strings:
    $a0 = { E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 6C 10 40 00 FF 25 70 10 40 00 FF 25 74 10 40 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 }

  condition:
    $a0 at pe.entry_point
}