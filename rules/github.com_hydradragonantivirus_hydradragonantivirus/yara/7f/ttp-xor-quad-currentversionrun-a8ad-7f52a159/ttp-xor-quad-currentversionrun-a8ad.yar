rule TTP_XOR_QUAD_CurrentVersionRun_a8ad {
  strings:
    $key_a8ad = { fb c2 [2] df cc [2] f4 e0 [2] da c2 [2] ce d9 [2] c1 c3 [2] df de [2] dd df [2] c6 d9 [2] da de [2] c6 f1 }

  condition:
    any of them
}