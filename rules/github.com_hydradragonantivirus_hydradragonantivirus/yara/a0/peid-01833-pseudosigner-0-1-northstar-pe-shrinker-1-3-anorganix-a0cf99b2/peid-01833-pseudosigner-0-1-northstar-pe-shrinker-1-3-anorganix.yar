rule PEiD_01833_PseudoSigner_0_1__NorthStar_PE_Shrinker_1_3_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [NorthStar PE Shrinker 1.3] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 E9 }

  condition:
    $a
}