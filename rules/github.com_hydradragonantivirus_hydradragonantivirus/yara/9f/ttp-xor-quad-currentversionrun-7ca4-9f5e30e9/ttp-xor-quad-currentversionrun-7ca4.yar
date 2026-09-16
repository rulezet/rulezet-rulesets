rule TTP_XOR_QUAD_CurrentVersionRun_7ca4 {
  strings:
    $key_7ca4 = { 2f cb [2] 0b c5 [2] 20 e9 [2] 0e cb [2] 1a d0 [2] 15 ca [2] 0b d7 [2] 09 d6 [2] 12 d0 [2] 0e d7 [2] 12 f8 }

  condition:
    any of them
}