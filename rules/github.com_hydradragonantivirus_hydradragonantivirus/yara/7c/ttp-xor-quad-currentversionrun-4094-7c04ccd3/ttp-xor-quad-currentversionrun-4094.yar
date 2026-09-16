rule TTP_XOR_QUAD_CurrentVersionRun_4094 {
  strings:
    $key_4094 = { 13 fb [2] 37 f5 [2] 1c d9 [2] 32 fb [2] 26 e0 [2] 29 fa [2] 37 e7 [2] 35 e6 [2] 2e e0 [2] 32 e7 [2] 2e c8 }

  condition:
    any of them
}