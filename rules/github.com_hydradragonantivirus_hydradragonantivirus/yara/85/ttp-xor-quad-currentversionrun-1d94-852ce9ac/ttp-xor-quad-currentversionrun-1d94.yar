rule TTP_XOR_QUAD_CurrentVersionRun_1d94 {
  strings:
    $key_1d94 = { 4e fb [2] 6a f5 [2] 41 d9 [2] 6f fb [2] 7b e0 [2] 74 fa [2] 6a e7 [2] 68 e6 [2] 73 e0 [2] 6f e7 [2] 73 c8 }

  condition:
    any of them
}