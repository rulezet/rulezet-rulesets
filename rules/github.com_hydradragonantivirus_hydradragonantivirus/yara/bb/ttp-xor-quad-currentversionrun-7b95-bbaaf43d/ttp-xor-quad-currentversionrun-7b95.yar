rule TTP_XOR_QUAD_CurrentVersionRun_7b95 {
  strings:
    $key_7b95 = { 28 fa [2] 0c f4 [2] 27 d8 [2] 09 fa [2] 1d e1 [2] 12 fb [2] 0c e6 [2] 0e e7 [2] 15 e1 [2] 09 e6 [2] 15 c9 }

  condition:
    any of them
}