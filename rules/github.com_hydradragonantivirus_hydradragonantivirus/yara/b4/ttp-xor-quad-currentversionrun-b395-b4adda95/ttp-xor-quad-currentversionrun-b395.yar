rule TTP_XOR_QUAD_CurrentVersionRun_b395 {
  strings:
    $key_b395 = { e0 fa [2] c4 f4 [2] ef d8 [2] c1 fa [2] d5 e1 [2] da fb [2] c4 e6 [2] c6 e7 [2] dd e1 [2] c1 e6 [2] dd c9 }

  condition:
    any of them
}