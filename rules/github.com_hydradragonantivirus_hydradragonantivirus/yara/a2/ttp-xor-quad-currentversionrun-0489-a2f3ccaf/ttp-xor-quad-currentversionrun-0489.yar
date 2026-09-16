rule TTP_XOR_QUAD_CurrentVersionRun_0489 {
  strings:
    $key_0489 = { 57 e6 [2] 73 e8 [2] 58 c4 [2] 76 e6 [2] 62 fd [2] 6d e7 [2] 73 fa [2] 71 fb [2] 6a fd [2] 76 fa [2] 6a d5 }

  condition:
    any of them
}