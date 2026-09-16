rule TTP_XOR_QUAD_CurrentVersionRun_7095 {
  strings:
    $key_7095 = { 23 fa [2] 07 f4 [2] 2c d8 [2] 02 fa [2] 16 e1 [2] 19 fb [2] 07 e6 [2] 05 e7 [2] 1e e1 [2] 02 e6 [2] 1e c9 }

  condition:
    any of them
}