rule TTP_XOR_QUAD_CurrentVersionRun_4d89 {
  strings:
    $key_4d89 = { 1e e6 [2] 3a e8 [2] 11 c4 [2] 3f e6 [2] 2b fd [2] 24 e7 [2] 3a fa [2] 38 fb [2] 23 fd [2] 3f fa [2] 23 d5 }

  condition:
    any of them
}