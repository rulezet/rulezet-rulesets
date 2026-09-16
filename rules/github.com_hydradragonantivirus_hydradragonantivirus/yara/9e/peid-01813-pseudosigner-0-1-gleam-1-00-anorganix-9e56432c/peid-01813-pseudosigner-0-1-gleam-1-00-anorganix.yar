rule PEiD_01813_PseudoSigner_0_1__Gleam_1_00_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Gleam 1.00] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 EB 0B 83 EC 0C 53 56 57 E8 24 02 00 FF E9 }

  condition:
    $a
}