import "pe"
rule ASPack_v1_08_03 {
  strings:
    $a0 = { 60 E8 00 00 00 00 5D 81 ED 0A 4A 44 00 BB 04 4A 44 00 03 DD 2B 9D B1 50 44 00 83 BD AC 50 44 00 00 89 9D BB 4E }

  condition:
    $a0 at pe.entry_point
}