rule TTP_XOR_QUAD_CurrentVersionRun_ada7 {
  strings:
    $key_ada7 = { fe c8 [2] da c6 [2] f1 ea [2] df c8 [2] cb d3 [2] c4 c9 [2] da d4 [2] d8 d5 [2] c3 d3 [2] df d4 [2] c3 fb }

  condition:
    any of them
}