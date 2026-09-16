rule TTP_XOR_QUAD_CurrentVersionRun_3ea5 {
  strings:
    $key_3ea5 = { 6d ca [2] 49 c4 [2] 62 e8 [2] 4c ca [2] 58 d1 [2] 57 cb [2] 49 d6 [2] 4b d7 [2] 50 d1 [2] 4c d6 [2] 50 f9 }

  condition:
    any of them
}