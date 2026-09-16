import "pe"
rule Private_EXE_v2_0a {
  strings:
    $a0 = { 53 E8 00 00 00 00 5B 8B C3 2D }

  condition:
    $a0 at pe.entry_point
}