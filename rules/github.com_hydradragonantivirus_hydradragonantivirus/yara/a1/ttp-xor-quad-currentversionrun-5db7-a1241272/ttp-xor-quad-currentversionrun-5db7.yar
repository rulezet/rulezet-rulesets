rule TTP_XOR_QUAD_CurrentVersionRun_5db7 {
  strings:
    $key_5db7 = { 0e d8 [2] 2a d6 [2] 01 fa [2] 2f d8 [2] 3b c3 [2] 34 d9 [2] 2a c4 [2] 28 c5 [2] 33 c3 [2] 2f c4 [2] 33 eb }

  condition:
    any of them
}