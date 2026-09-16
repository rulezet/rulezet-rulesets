import "pe"
rule __PseudoSigner_0_1_rule__Yoda_s_Protector_1_02______Anorganix {
  strings:
    $a0 = { E8 03 00 00 00 EB 01 90 90 E9 }

  condition:
    $a0 at pe.entry_point
}