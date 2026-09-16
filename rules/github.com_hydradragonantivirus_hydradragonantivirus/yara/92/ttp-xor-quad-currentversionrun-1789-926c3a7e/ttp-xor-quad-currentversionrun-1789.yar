rule TTP_XOR_QUAD_CurrentVersionRun_1789 {
  strings:
    $key_1789 = { 44 e6 [2] 60 e8 [2] 4b c4 [2] 65 e6 [2] 71 fd [2] 7e e7 [2] 60 fa [2] 62 fb [2] 79 fd [2] 65 fa [2] 79 d5 }

  condition:
    any of them
}