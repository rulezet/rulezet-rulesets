import "pe"
rule __PseudoSigner_0_1_rule__MEW_11_SE_1_0______Anorganix {
  strings:
    $a0 = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 E9 }

  condition:
    $a0 at pe.entry_point
}