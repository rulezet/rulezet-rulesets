rule TTP_XOR_QUAD_CurrentVersionRun_3094 {
  strings:
    $key_3094 = { 63 fb [2] 47 f5 [2] 6c d9 [2] 42 fb [2] 56 e0 [2] 59 fa [2] 47 e7 [2] 45 e6 [2] 5e e0 [2] 42 e7 [2] 5e c8 }

  condition:
    any of them
}