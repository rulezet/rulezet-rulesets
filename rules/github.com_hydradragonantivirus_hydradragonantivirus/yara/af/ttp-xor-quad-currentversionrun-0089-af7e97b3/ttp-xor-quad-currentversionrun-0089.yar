rule TTP_XOR_QUAD_CurrentVersionRun_0089 {
  strings:
    $key_0089 = { 53 e6 [2] 77 e8 [2] 5c c4 [2] 72 e6 [2] 66 fd [2] 69 e7 [2] 77 fa [2] 75 fb [2] 6e fd [2] 72 fa [2] 6e d5 }

  condition:
    any of them
}