rule TTP_XOR_QUAD_CurrentVersionRun_6789 {
  strings:
    $key_6789 = { 34 e6 [2] 10 e8 [2] 3b c4 [2] 15 e6 [2] 01 fd [2] 0e e7 [2] 10 fa [2] 12 fb [2] 09 fd [2] 15 fa [2] 09 d5 }

  condition:
    any of them
}