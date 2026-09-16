rule TTP_XOR_QUAD_CurrentVersionRun_2094 {
  strings:
    $key_2094 = { 73 fb [2] 57 f5 [2] 7c d9 [2] 52 fb [2] 46 e0 [2] 49 fa [2] 57 e7 [2] 55 e6 [2] 4e e0 [2] 52 e7 [2] 4e c8 }

  condition:
    any of them
}