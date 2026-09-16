rule TTP_XOR_QUAD_CurrentVersionRun_7d95 {
  strings:
    $key_7d95 = { 2e fa [2] 0a f4 [2] 21 d8 [2] 0f fa [2] 1b e1 [2] 14 fb [2] 0a e6 [2] 08 e7 [2] 13 e1 [2] 0f e6 [2] 13 c9 }

  condition:
    any of them
}