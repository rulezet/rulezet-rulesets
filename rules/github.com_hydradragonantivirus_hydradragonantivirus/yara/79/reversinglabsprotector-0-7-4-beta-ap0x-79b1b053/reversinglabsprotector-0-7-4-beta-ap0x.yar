import "pe"
rule ReversingLabsProtector_0_7_4_beta____Ap0x {
  strings:
    $a0 = { 68 00 00 41 00 E8 01 00 00 00 C3 C3 }

  condition:
    $a0 at pe.entry_point
}