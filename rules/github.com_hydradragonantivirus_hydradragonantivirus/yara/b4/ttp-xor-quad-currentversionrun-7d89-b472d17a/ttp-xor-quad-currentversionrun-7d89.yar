rule TTP_XOR_QUAD_CurrentVersionRun_7d89 {
  strings:
    $key_7d89 = { 2e e6 [2] 0a e8 [2] 21 c4 [2] 0f e6 [2] 1b fd [2] 14 e7 [2] 0a fa [2] 08 fb [2] 13 fd [2] 0f fa [2] 13 d5 }

  condition:
    any of them
}