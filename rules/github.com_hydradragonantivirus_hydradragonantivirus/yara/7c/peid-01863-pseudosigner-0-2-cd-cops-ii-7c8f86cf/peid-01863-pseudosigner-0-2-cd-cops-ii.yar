rule PEiD_01863_PseudoSigner_0_2__CD_Cops_II__ {
  meta:
    description = "[PseudoSigner 0.2 [CD-Cops II]]"
    ep_only     = "true"

  strings:
    $a = { 53 60 BD 90 90 90 90 8D 45 90 8D 5D 90 E8 00 00 00 00 8D 01 }

  condition:
    $a
}