rule TTP_XOR_QUAD_CurrentVersionRun_6895 {
  strings:
    $key_6895 = { 3b fa [2] 1f f4 [2] 34 d8 [2] 1a fa [2] 0e e1 [2] 01 fb [2] 1f e6 [2] 1d e7 [2] 06 e1 [2] 1a e6 [2] 06 c9 }

  condition:
    any of them
}