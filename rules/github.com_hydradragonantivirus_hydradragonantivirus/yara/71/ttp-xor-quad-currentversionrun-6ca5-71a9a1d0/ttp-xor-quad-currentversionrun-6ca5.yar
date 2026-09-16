rule TTP_XOR_QUAD_CurrentVersionRun_6ca5 {
  strings:
    $key_6ca5 = { 3f ca [2] 1b c4 [2] 30 e8 [2] 1e ca [2] 0a d1 [2] 05 cb [2] 1b d6 [2] 19 d7 [2] 02 d1 [2] 1e d6 [2] 02 f9 }

  condition:
    any of them
}