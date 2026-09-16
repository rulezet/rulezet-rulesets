rule PEiD_01891_PseudoSigner_0_2__Video_Lan_Client__ {
  meta:
    description = "[PseudoSigner 0.2 [Video-Lan-Client]]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 83 EC 08 90 90 90 90 90 90 90 90 90 90 90 90 90 90 01 FF FF 01 01 01 00 01 90 90 90 90 90 90 90 90 90 90 90 90 90 90 00 01 00 01 00 01 90 90 00 01 }

  condition:
    $a
}