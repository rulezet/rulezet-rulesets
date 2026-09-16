rule TTP_XOR_QUAD_CurrentVersionRun_0094 {
  strings:
    $key_0094 = { 53 fb [2] 77 f5 [2] 5c d9 [2] 72 fb [2] 66 e0 [2] 69 fa [2] 77 e7 [2] 75 e6 [2] 6e e0 [2] 72 e7 [2] 6e c8 }

  condition:
    any of them
}