rule TTP_XOR_QUAD_CurrentVersionRun_2ea5 {
  strings:
    $key_2ea5 = { 7d ca [2] 59 c4 [2] 72 e8 [2] 5c ca [2] 48 d1 [2] 47 cb [2] 59 d6 [2] 5b d7 [2] 40 d1 [2] 5c d6 [2] 40 f9 }

  condition:
    any of them
}