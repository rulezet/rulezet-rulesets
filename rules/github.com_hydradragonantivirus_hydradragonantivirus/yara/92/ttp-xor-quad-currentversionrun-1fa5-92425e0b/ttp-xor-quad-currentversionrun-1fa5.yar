rule TTP_XOR_QUAD_CurrentVersionRun_1fa5 {
  strings:
    $key_1fa5 = { 4c ca [2] 68 c4 [2] 43 e8 [2] 6d ca [2] 79 d1 [2] 76 cb [2] 68 d6 [2] 6a d7 [2] 71 d1 [2] 6d d6 [2] 71 f9 }

  condition:
    any of them
}