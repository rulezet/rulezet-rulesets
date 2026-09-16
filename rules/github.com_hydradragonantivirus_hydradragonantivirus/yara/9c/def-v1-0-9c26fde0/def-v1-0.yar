import "pe"
rule DEF_v1_0 {
  strings:
    $a0 = { BE ?? 01 40 00 6A ?? 59 80 7E 07 00 74 11 8B 46 0C 05 00 00 40 00 8B 56 10 30 10 40 4A 75 FA 83 C6 28 E2 E4 68 ?? 10 40 00 C3 }
    $a1 = { BE ?? 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}