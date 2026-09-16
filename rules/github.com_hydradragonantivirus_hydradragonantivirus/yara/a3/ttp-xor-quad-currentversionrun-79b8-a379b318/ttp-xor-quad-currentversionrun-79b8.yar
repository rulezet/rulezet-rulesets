rule TTP_XOR_QUAD_CurrentVersionRun_79b8 {
  strings:
    $key_79b8 = { 2a d7 [2] 0e d9 [2] 25 f5 [2] 0b d7 [2] 1f cc [2] 10 d6 [2] 0e cb [2] 0c ca [2] 17 cc [2] 0b cb [2] 17 e4 }

  condition:
    any of them
}