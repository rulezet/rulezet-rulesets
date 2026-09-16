rule TTP_XOR_QUAD_CurrentVersionRun_b189 {
  strings:
    $key_b189 = { e2 e6 [2] c6 e8 [2] ed c4 [2] c3 e6 [2] d7 fd [2] d8 e7 [2] c6 fa [2] c4 fb [2] df fd [2] c3 fa [2] df d5 }

  condition:
    any of them
}