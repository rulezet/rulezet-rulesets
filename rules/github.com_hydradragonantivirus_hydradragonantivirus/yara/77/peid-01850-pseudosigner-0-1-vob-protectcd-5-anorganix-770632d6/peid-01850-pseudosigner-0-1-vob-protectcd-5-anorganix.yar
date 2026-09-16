rule PEiD_01850_PseudoSigner_0_1__VOB_ProtectCD_5_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [VOB ProtectCD 5] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 36 3E 26 8A C0 60 E8 00 00 00 00 E9 }

  condition:
    $a
}