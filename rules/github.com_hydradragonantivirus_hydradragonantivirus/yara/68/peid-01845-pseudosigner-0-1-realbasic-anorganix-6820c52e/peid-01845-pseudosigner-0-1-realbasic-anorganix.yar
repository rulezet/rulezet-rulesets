rule PEiD_01845_PseudoSigner_0_1__REALBasic_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [REALBasic] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 E9 }

  condition:
    $a
}