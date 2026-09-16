rule TTP_XOR_QUAD_CurrentVersionRun_0cb7 {
  strings:
    $key_0cb7 = { 5f d8 [2] 7b d6 [2] 50 fa [2] 7e d8 [2] 6a c3 [2] 65 d9 [2] 7b c4 [2] 79 c5 [2] 62 c3 [2] 7e c4 [2] 62 eb }

  condition:
    any of them
}