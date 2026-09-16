rule PEiD_01846_PseudoSigner_0_1__Ste_lth_PE_1_01__ {
  meta:
    description = "[PseudoSigner 0.1 [Ste@lth PE 1.01]]"
    ep_only     = "true"

  strings:
    $a = { 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 0B C0 BA ?? ?? ?? ?? FF E2 BA E0 10 40 00 B8 68 24 1A 40 89 02 83 C2 03 B8 40 00 E8 EE 89 02 83 C2 FD FF E2 2D 3D 5B 20 48 69 64 65 50 45 20 5D 3D 2D 90 00 00 00 }

  condition:
    $a
}