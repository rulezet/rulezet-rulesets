rule TTP_XOR_QUAD_CurrentVersionRun_e994 {
  strings:
    $key_e994 = { ba fb [2] 9e f5 [2] b5 d9 [2] 9b fb [2] 8f e0 [2] 80 fa [2] 9e e7 [2] 9c e6 [2] 87 e0 [2] 9b e7 [2] 87 c8 }

  condition:
    any of them
}