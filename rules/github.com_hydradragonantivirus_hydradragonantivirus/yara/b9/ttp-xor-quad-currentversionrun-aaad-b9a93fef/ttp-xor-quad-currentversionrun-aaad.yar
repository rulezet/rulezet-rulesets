rule TTP_XOR_QUAD_CurrentVersionRun_aaad {
  strings:
    $key_aaad = { f9 c2 [2] dd cc [2] f6 e0 [2] d8 c2 [2] cc d9 [2] c3 c3 [2] dd de [2] df df [2] c4 d9 [2] d8 de [2] c4 f1 }

  condition:
    any of them
}