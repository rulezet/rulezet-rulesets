rule TTP_XOR_QUAD_CurrentVersionRun_1c94 {
  strings:
    $key_1c94 = { 4f fb [2] 6b f5 [2] 40 d9 [2] 6e fb [2] 7a e0 [2] 75 fa [2] 6b e7 [2] 69 e6 [2] 72 e0 [2] 6e e7 [2] 72 c8 }

  condition:
    any of them
}