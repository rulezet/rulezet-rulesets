rule TTP_XOR_QUAD_CurrentVersionRun_2db7 {
  strings:
    $key_2db7 = { 7e d8 [2] 5a d6 [2] 71 fa [2] 5f d8 [2] 4b c3 [2] 44 d9 [2] 5a c4 [2] 58 c5 [2] 43 c3 [2] 5f c4 [2] 43 eb }

  condition:
    any of them
}