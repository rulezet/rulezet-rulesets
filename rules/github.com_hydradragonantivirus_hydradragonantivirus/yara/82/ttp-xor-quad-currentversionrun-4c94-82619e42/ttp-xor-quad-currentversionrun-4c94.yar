rule TTP_XOR_QUAD_CurrentVersionRun_4c94 {
  strings:
    $key_4c94 = { 1f fb [2] 3b f5 [2] 10 d9 [2] 3e fb [2] 2a e0 [2] 25 fa [2] 3b e7 [2] 39 e6 [2] 22 e0 [2] 3e e7 [2] 22 c8 }

  condition:
    any of them
}