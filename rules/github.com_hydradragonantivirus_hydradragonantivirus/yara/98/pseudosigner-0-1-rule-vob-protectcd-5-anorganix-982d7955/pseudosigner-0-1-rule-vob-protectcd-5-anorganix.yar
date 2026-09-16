import "pe"
rule __PseudoSigner_0_1_rule__VOB_ProtectCD_5______Anorganix {
  strings:
    $a0 = { 36 3E 26 8A C0 60 E8 00 00 00 00 E9 }

  condition:
    $a0 at pe.entry_point
}