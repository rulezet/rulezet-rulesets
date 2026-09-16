rule TTP_XOR_QUAD_CurrentVersionRun_5d94 {
  strings:
    $key_5d94 = { 0e fb [2] 2a f5 [2] 01 d9 [2] 2f fb [2] 3b e0 [2] 34 fa [2] 2a e7 [2] 28 e6 [2] 33 e0 [2] 2f e7 [2] 33 c8 }

  condition:
    any of them
}