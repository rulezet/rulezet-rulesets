rule PEiD_01866_PseudoSigner_0_2__Crunch_PE_Heuristic__ {
  meta:
    description = "[PseudoSigner 0.2 [Crunch/PE Heuristic]]"
    ep_only     = "true"

  strings:
    $a = { 55 E8 0E 00 00 00 5D 83 ED 06 8B C5 55 60 89 AD ?? ?? ?? ?? 2B 85 00 00 00 00 }

  condition:
    $a
}