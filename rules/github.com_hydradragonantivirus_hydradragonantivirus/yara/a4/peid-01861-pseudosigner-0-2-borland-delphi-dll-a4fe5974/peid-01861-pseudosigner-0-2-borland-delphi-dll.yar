rule PEiD_01861_PseudoSigner_0_2__Borland_Delphi_DLL__ {
  meta:
    description = "[PseudoSigner 0.2 [Borland Delphi DLL]]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 B4 B8 90 90 90 90 E8 00 00 00 00 E8 00 00 00 00 8D 40 00 }

  condition:
    $a
}