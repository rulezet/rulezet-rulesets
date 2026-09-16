import "pe"
rule __PseudoSigner_0_2_rule___BJFNT_1_2______Anorganix {
  strings:
    $a0 = { EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 00 }

  condition:
    $a0 at pe.entry_point
}