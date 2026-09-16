import "pe"
rule PEBundle_v3_10 {
  strings:
    $a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD ?? ?? ?? ?? 40 00 01 }

  condition:
    $a0 at pe.entry_point
}