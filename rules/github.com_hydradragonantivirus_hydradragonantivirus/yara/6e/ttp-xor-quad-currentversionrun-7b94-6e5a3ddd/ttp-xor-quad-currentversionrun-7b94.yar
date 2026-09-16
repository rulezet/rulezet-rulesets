rule TTP_XOR_QUAD_CurrentVersionRun_7b94 {
  strings:
    $key_7b94 = { 28 fb [2] 0c f5 [2] 27 d9 [2] 09 fb [2] 1d e0 [2] 12 fa [2] 0c e7 [2] 0e e6 [2] 15 e0 [2] 09 e7 [2] 15 c8 }

  condition:
    any of them
}