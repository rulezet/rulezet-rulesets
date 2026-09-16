rule TTP_XOR_QUAD_CurrentVersionRun_4db7 {
  strings:
    $key_4db7 = { 1e d8 [2] 3a d6 [2] 11 fa [2] 3f d8 [2] 2b c3 [2] 24 d9 [2] 3a c4 [2] 38 c5 [2] 23 c3 [2] 3f c4 [2] 23 eb }

  condition:
    any of them
}