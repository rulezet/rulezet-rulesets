rule TTP_XOR_QUAD_CurrentVersionRun_4994 {
  strings:
    $key_4994 = { 1a fb [2] 3e f5 [2] 15 d9 [2] 3b fb [2] 2f e0 [2] 20 fa [2] 3e e7 [2] 3c e6 [2] 27 e0 [2] 3b e7 [2] 27 c8 }

  condition:
    any of them
}