rule TTP_XOR_QUAD_CurrentVersionRun_5f89 {
  strings:
    $key_5f89 = { 0c e6 [2] 28 e8 [2] 03 c4 [2] 2d e6 [2] 39 fd [2] 36 e7 [2] 28 fa [2] 2a fb [2] 31 fd [2] 2d fa [2] 31 d5 }

  condition:
    any of them
}