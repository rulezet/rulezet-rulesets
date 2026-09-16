rule TTP_XOR_QUAD_CurrentVersionRun_4d94 {
  strings:
    $key_4d94 = { 1e fb [2] 3a f5 [2] 11 d9 [2] 3f fb [2] 2b e0 [2] 24 fa [2] 3a e7 [2] 38 e6 [2] 23 e0 [2] 3f e7 [2] 23 c8 }

  condition:
    any of them
}