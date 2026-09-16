rule TTP_XOR_QUAD_CurrentVersionRun_7ca5 {
  strings:
    $key_7ca5 = { 2f ca [2] 0b c4 [2] 20 e8 [2] 0e ca [2] 1a d1 [2] 15 cb [2] 0b d6 [2] 09 d7 [2] 12 d1 [2] 0e d6 [2] 12 f9 }

  condition:
    any of them
}