rule PEiD_01878_PseudoSigner_0_2__MEW_11_SE_1_0__ {
  meta:
    description = "[PseudoSigner 0.2 [MEW 11 SE 1.0]]"
    ep_only     = "true"

  strings:
    $a = { E9 09 00 00 00 00 00 00 02 00 00 00 0C 90 }

  condition:
    $a
}