rule TTP_XOR_QUAD_CurrentVersionRun_79b7 {
  strings:
    $key_79b7 = { 2a d8 [2] 0e d6 [2] 25 fa [2] 0b d8 [2] 1f c3 [2] 10 d9 [2] 0e c4 [2] 0c c5 [2] 17 c3 [2] 0b c4 [2] 17 eb }

  condition:
    any of them
}