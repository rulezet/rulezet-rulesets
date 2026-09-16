rule TTP_XOR_QUAD_CurrentVersionRun_b3b7 {
  strings:
    $key_b3b7 = { e0 d8 [2] c4 d6 [2] ef fa [2] c1 d8 [2] d5 c3 [2] da d9 [2] c4 c4 [2] c6 c5 [2] dd c3 [2] c1 c4 [2] dd eb }

  condition:
    any of them
}