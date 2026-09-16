rule TTP_XOR_QUAD_CurrentVersionRun_2d95 {
  strings:
    $key_2d95 = { 7e fa [2] 5a f4 [2] 71 d8 [2] 5f fa [2] 4b e1 [2] 44 fb [2] 5a e6 [2] 58 e7 [2] 43 e1 [2] 5f e6 [2] 43 c9 }

  condition:
    any of them
}