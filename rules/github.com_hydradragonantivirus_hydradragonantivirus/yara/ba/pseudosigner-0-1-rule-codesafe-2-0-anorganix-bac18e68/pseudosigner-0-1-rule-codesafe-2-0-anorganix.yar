import "pe"
rule __PseudoSigner_0_1_rule__CodeSafe_2_0______Anorganix {
  strings:
    $a0 = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 10 53 56 57 E8 C4 01 00 85 E9 }

  condition:
    $a0 at pe.entry_point
}