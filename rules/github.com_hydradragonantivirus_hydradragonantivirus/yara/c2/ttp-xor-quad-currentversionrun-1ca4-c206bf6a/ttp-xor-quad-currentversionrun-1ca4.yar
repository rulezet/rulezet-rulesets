rule TTP_XOR_QUAD_CurrentVersionRun_1ca4 {
  strings:
    $key_1ca4 = { 4f cb [2] 6b c5 [2] 40 e9 [2] 6e cb [2] 7a d0 [2] 75 ca [2] 6b d7 [2] 69 d6 [2] 72 d0 [2] 6e d7 [2] 72 f8 }

  condition:
    any of them
}