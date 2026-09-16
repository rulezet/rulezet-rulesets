rule TTP_XOR_QUAD_CurrentVersionRun_6f89 {
  strings:
    $key_6f89 = { 3c e6 [2] 18 e8 [2] 33 c4 [2] 1d e6 [2] 09 fd [2] 06 e7 [2] 18 fa [2] 1a fb [2] 01 fd [2] 1d fa [2] 01 d5 }

  condition:
    any of them
}