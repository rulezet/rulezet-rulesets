rule TTP_XOR_QUAD_CurrentVersionRun_7895 {
  strings:
    $key_7895 = { 2b fa [2] 0f f4 [2] 24 d8 [2] 0a fa [2] 1e e1 [2] 11 fb [2] 0f e6 [2] 0d e7 [2] 16 e1 [2] 0a e6 [2] 16 c9 }

  condition:
    any of them
}