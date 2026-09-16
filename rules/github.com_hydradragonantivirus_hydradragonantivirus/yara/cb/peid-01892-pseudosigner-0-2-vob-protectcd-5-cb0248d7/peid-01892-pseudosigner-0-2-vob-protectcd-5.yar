rule PEiD_01892_PseudoSigner_0_2__VOB_ProtectCD_5__ {
  meta:
    description = "[PseudoSigner 0.2 [VOB ProtectCD 5]]"
    ep_only     = "true"

  strings:
    $a = { 36 3E 26 8A C0 60 E8 00 00 00 00 }

  condition:
    $a
}