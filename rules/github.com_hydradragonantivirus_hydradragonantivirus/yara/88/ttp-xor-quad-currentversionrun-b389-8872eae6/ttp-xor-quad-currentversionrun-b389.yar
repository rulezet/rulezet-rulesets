rule TTP_XOR_QUAD_CurrentVersionRun_b389 {
  strings:
    $key_b389 = { e0 e6 [2] c4 e8 [2] ef c4 [2] c1 e6 [2] d5 fd [2] da e7 [2] c4 fa [2] c6 fb [2] dd fd [2] c1 fa [2] dd d5 }

  condition:
    any of them
}