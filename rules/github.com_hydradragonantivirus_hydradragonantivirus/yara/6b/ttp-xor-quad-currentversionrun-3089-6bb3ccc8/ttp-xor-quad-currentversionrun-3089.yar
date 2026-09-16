rule TTP_XOR_QUAD_CurrentVersionRun_3089 {
  strings:
    $key_3089 = { 63 e6 [2] 47 e8 [2] 6c c4 [2] 42 e6 [2] 56 fd [2] 59 e7 [2] 47 fa [2] 45 fb [2] 5e fd [2] 42 fa [2] 5e d5 }

  condition:
    any of them
}