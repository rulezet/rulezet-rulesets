rule TTP_XOR_QUAD_CurrentVersionRun_7789 {
  strings:
    $key_7789 = { 24 e6 [2] 00 e8 [2] 2b c4 [2] 05 e6 [2] 11 fd [2] 1e e7 [2] 00 fa [2] 02 fb [2] 19 fd [2] 05 fa [2] 19 d5 }

  condition:
    any of them
}