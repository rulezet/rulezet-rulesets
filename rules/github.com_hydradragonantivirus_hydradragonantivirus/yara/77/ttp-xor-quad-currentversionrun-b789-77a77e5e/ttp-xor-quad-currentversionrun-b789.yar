rule TTP_XOR_QUAD_CurrentVersionRun_b789 {
  strings:
    $key_b789 = { e4 e6 [2] c0 e8 [2] eb c4 [2] c5 e6 [2] d1 fd [2] de e7 [2] c0 fa [2] c2 fb [2] d9 fd [2] c5 fa [2] d9 d5 }

  condition:
    any of them
}