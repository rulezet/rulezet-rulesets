rule TTP_XOR_QUAD_CurrentVersionRun_b1aa {
  strings:
    $key_b1aa = { e2 c5 [2] c6 cb [2] ed e7 [2] c3 c5 [2] d7 de [2] d8 c4 [2] c6 d9 [2] c4 d8 [2] df de [2] c3 d9 [2] df f6 }

  condition:
    any of them
}