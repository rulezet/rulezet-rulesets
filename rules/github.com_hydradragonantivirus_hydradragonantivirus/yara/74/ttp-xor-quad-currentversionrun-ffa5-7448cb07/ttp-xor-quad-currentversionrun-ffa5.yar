rule TTP_XOR_QUAD_CurrentVersionRun_ffa5 {
  strings:
    $key_ffa5 = { ac ca [2] 88 c4 [2] a3 e8 [2] 8d ca [2] 99 d1 [2] 96 cb [2] 88 d6 [2] 8a d7 [2] 91 d1 [2] 8d d6 [2] 91 f9 }

  condition:
    any of them
}