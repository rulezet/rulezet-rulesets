import "pe"
rule __PseudoSigner_0_1_rule__PE_Intro_1_0______Anorganix {
  strings:
    $a0 = { 8B 04 24 9C 60 E8 14 00 00 00 5D 81 ED 0A 45 40 90 80 BD 67 44 40 90 90 0F 85 48 FF ED 0A E9 }

  condition:
    $a0 at pe.entry_point
}