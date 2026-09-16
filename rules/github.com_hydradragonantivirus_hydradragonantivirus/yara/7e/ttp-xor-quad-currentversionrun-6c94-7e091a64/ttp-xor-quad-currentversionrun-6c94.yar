rule TTP_XOR_QUAD_CurrentVersionRun_6c94 {
  strings:
    $key_6c94 = { 3f fb [2] 1b f5 [2] 30 d9 [2] 1e fb [2] 0a e0 [2] 05 fa [2] 1b e7 [2] 19 e6 [2] 02 e0 [2] 1e e7 [2] 02 c8 }

  condition:
    any of them
}