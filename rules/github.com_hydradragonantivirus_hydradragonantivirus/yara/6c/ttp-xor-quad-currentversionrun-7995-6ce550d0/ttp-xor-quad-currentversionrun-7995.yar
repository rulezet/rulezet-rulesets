rule TTP_XOR_QUAD_CurrentVersionRun_7995 {
  strings:
    $key_7995 = { 2a fa [2] 0e f4 [2] 25 d8 [2] 0b fa [2] 1f e1 [2] 10 fb [2] 0e e6 [2] 0c e7 [2] 17 e1 [2] 0b e6 [2] 17 c9 }

  condition:
    any of them
}