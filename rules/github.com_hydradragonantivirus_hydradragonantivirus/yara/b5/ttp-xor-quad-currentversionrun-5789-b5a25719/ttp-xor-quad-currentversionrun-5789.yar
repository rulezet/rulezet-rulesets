rule TTP_XOR_QUAD_CurrentVersionRun_5789 {
  strings:
    $key_5789 = { 04 e6 [2] 20 e8 [2] 0b c4 [2] 25 e6 [2] 31 fd [2] 3e e7 [2] 20 fa [2] 22 fb [2] 39 fd [2] 25 fa [2] 39 d5 }

  condition:
    any of them
}