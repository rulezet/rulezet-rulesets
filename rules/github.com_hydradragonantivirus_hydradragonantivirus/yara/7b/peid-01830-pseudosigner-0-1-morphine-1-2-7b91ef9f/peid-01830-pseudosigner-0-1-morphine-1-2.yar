rule PEiD_01830_PseudoSigner_0_1__Morphine_1_2__ {
  meta:
    description = "[PseudoSigner 0.1 [Morphine 1.2]]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 06 00 90 90 90 90 90 90 90 90 EB 08 E8 90 00 00 00 66 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 51 66 90 90 90 59 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

  condition:
    $a
}