rule TTP_XOR_QUAD_CurrentVersionRun_5d89 {
  strings:
    $key_5d89 = { 0e e6 [2] 2a e8 [2] 01 c4 [2] 2f e6 [2] 3b fd [2] 34 e7 [2] 2a fa [2] 28 fb [2] 33 fd [2] 2f fa [2] 33 d5 }

  condition:
    any of them
}