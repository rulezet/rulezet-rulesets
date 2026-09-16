rule PEiD_01849_PseudoSigner_0_1__Video_Lan_Client_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Video-Lan-Client] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 E9 }

  condition:
    $a
}