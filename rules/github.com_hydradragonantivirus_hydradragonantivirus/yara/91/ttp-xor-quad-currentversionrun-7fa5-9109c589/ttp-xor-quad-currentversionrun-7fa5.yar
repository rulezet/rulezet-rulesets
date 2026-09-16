rule TTP_XOR_QUAD_CurrentVersionRun_7fa5 {
  strings:
    $key_7fa5 = { 2c ca [2] 08 c4 [2] 23 e8 [2] 0d ca [2] 19 d1 [2] 16 cb [2] 08 d6 [2] 0a d7 [2] 11 d1 [2] 0d d6 [2] 11 f9 }

  condition:
    any of them
}