rule PEiD_01889_PseudoSigner_0_2__REALBasic__ {
  meta:
    description = "[PseudoSigner 0.2 [REALBasic]]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 90 90 90 90 90 90 90 90 90 90 50 90 90 90 90 90 00 01 }

  condition:
    $a
}