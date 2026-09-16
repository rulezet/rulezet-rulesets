rule TTP_XOR_QUAD_CurrentVersionRun_2ca5 {
  strings:
    $key_2ca5 = { 7f ca [2] 5b c4 [2] 70 e8 [2] 5e ca [2] 4a d1 [2] 45 cb [2] 5b d6 [2] 59 d7 [2] 42 d1 [2] 5e d6 [2] 42 f9 }

  condition:
    any of them
}