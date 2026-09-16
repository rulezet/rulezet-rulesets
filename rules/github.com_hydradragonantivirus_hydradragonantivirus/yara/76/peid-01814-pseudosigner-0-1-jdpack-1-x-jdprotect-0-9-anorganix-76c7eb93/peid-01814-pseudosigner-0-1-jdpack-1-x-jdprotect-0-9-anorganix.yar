rule PEiD_01814_PseudoSigner_0_1__JDPack_1_x___JDProtect_0_9_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [JDPack 1.x / JDProtect 0.9] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 22 00 00 00 5D 8B D5 81 ED 90 90 90 90 2B 95 90 90 90 90 81 EA 06 90 90 90 89 95 90 90 90 90 83 BD 45 00 01 00 01 E9 }

  condition:
    $a
}