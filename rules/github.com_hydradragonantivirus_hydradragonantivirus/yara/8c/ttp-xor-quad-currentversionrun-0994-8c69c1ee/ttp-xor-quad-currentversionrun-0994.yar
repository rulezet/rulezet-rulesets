rule TTP_XOR_QUAD_CurrentVersionRun_0994 {
  strings:
    $key_0994 = { 5a fb [2] 7e f5 [2] 55 d9 [2] 7b fb [2] 6f e0 [2] 60 fa [2] 7e e7 [2] 7c e6 [2] 67 e0 [2] 7b e7 [2] 67 c8 }

  condition:
    any of them
}