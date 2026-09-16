rule PEiD_01807_PseudoSigner_0_1__Crunch_PE_Heuristic_____Anorganix_ {
  meta:
    description = "[PseudoSigner 0.1 [Crunch/PE Heuristic] -> Anorganix]"
    ep_only     = "true"

  strings:
    $a = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 E9 }

  condition:
    $a
}