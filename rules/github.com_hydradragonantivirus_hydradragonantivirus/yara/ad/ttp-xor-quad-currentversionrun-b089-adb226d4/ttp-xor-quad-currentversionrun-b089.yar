rule TTP_XOR_QUAD_CurrentVersionRun_b089 {
  strings:
    $key_b089 = { e3 e6 [2] c7 e8 [2] ec c4 [2] c2 e6 [2] d6 fd [2] d9 e7 [2] c7 fa [2] c5 fb [2] de fd [2] c2 fa [2] de d5 }

  condition:
    any of them
}