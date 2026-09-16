rule TTP_XOR_QUAD_CurrentVersionRun_1b95 {
  strings:
    $key_1b95 = { 48 fa [2] 6c f4 [2] 47 d8 [2] 69 fa [2] 7d e1 [2] 72 fb [2] 6c e6 [2] 6e e7 [2] 75 e1 [2] 69 e6 [2] 75 c9 }

  condition:
    any of them
}