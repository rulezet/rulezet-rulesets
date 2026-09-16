rule PEiD_01867_PseudoSigner_0_2__DEF_1_0__ {
  meta:
    description = "[PseudoSigner 0.2 [DEF 1.0]]"
    ep_only     = "true"

  strings:
    $a = { BE 00 01 40 00 6A 05 59 80 7E 07 00 74 11 8B 46 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 83 C1 01 }

  condition:
    $a
}