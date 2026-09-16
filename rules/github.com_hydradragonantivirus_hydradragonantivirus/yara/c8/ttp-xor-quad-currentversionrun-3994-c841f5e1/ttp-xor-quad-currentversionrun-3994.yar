rule TTP_XOR_QUAD_CurrentVersionRun_3994 {
  strings:
    $key_3994 = { 6a fb [2] 4e f5 [2] 65 d9 [2] 4b fb [2] 5f e0 [2] 50 fa [2] 4e e7 [2] 4c e6 [2] 57 e0 [2] 4b e7 [2] 57 c8 }

  condition:
    any of them
}