rule PEiD_01895_PseudoSigner_0_2__ZCode_1_01__ {
  meta:
    description = "[PseudoSigner 0.2 [ZCode 1.01]]"
    ep_only     = "true"

  strings:
    $a = { E9 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E9 FB FF FF FF C3 68 00 00 00 00 64 FF 35 00 00 00 00 }

  condition:
    $a
}