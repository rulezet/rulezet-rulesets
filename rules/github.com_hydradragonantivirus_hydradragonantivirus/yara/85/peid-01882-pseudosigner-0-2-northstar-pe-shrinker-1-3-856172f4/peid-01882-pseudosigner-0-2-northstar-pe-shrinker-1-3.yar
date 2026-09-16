rule PEiD_01882_PseudoSigner_0_2__NorthStar_PE_Shrinker_1_3__ {
  meta:
    description = "[PseudoSigner 0.2 [NorthStar PE Shrinker 1.3]]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 00 00 00 00 }

  condition:
    $a
}