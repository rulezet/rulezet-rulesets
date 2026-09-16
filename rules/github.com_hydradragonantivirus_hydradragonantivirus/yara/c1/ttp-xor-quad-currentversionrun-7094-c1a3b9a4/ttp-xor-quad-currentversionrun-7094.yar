rule TTP_XOR_QUAD_CurrentVersionRun_7094 {
  strings:
    $key_7094 = { 23 fb [2] 07 f5 [2] 2c d9 [2] 02 fb [2] 16 e0 [2] 19 fa [2] 07 e7 [2] 05 e6 [2] 1e e0 [2] 02 e7 [2] 1e c8 }

  condition:
    any of them
}