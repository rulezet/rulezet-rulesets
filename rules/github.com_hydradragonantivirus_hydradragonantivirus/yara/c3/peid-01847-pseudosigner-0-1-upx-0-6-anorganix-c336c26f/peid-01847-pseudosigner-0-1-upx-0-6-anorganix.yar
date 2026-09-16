rule PEiD_01847_PseudoSigner_0_1__UPX_0_6_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [UPX 0.6] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 83 E8 3D 50 8D B8 00 00 00 FF 57 8D B0 E8 00 00 00 E9 }

  condition:
    $a
}