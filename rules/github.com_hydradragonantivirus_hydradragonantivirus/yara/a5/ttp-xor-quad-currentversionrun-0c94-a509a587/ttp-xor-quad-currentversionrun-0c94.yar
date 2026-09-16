rule TTP_XOR_QUAD_CurrentVersionRun_0c94 {
  strings:
    $key_0c94 = { 5f fb [2] 7b f5 [2] 50 d9 [2] 7e fb [2] 6a e0 [2] 65 fa [2] 7b e7 [2] 79 e6 [2] 62 e0 [2] 7e e7 [2] 62 c8 }

  condition:
    any of them
}