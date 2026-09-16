rule TTP_XOR_QUAD_CurrentVersionRun_1f89 {
  strings:
    $key_1f89 = { 4c e6 [2] 68 e8 [2] 43 c4 [2] 6d e6 [2] 79 fd [2] 76 e7 [2] 68 fa [2] 6a fb [2] 71 fd [2] 6d fa [2] 71 d5 }

  condition:
    any of them
}