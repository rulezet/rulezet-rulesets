import "pe"
rule Armadillo_v1_77 {
  strings:
    $a0 = { 55 8B EC 6A FF 68 B0 71 40 00 68 6C 37 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }

  condition:
    $a0 at pe.entry_point
}