rule TTP_XOR_QUAD_CurrentVersionRun_5ea5 {
  strings:
    $key_5ea5 = { 0d ca [2] 29 c4 [2] 02 e8 [2] 2c ca [2] 38 d1 [2] 37 cb [2] 29 d6 [2] 2b d7 [2] 30 d1 [2] 2c d6 [2] 30 f9 }

  condition:
    any of them
}