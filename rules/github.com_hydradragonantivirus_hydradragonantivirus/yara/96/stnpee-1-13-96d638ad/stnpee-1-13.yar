import "pe"
rule STNPEE_1_13 {
  strings:
    $a0 = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 97 3B 40 00 }

  condition:
    $a0 at pe.entry_point
}