rule TTP_XOR_QUAD_CurrentVersionRun_7ea5 {
  strings:
    $key_7ea5 = { 2d ca [2] 09 c4 [2] 22 e8 [2] 0c ca [2] 18 d1 [2] 17 cb [2] 09 d6 [2] 0b d7 [2] 10 d1 [2] 0c d6 [2] 10 f9 }

  condition:
    any of them
}