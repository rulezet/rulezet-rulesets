rule TTP_XOR_QUAD_CurrentVersionRun_5d95 {
  strings:
    $key_5d95 = { 0e fa [2] 2a f4 [2] 01 d8 [2] 2f fa [2] 3b e1 [2] 34 fb [2] 2a e6 [2] 28 e7 [2] 33 e1 [2] 2f e6 [2] 33 c9 }

  condition:
    any of them
}