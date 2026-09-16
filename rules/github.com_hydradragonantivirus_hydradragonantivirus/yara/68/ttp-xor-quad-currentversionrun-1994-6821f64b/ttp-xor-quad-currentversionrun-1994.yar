rule TTP_XOR_QUAD_CurrentVersionRun_1994 {
  strings:
    $key_1994 = { 4a fb [2] 6e f5 [2] 45 d9 [2] 6b fb [2] 7f e0 [2] 70 fa [2] 6e e7 [2] 6c e6 [2] 77 e0 [2] 6b e7 [2] 77 c8 }

  condition:
    any of them
}