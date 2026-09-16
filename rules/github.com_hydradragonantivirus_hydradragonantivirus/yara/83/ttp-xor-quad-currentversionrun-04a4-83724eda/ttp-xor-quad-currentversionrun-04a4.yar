rule TTP_XOR_QUAD_CurrentVersionRun_04a4 {
  strings:
    $key_04a4 = { 57 cb [2] 73 c5 [2] 58 e9 [2] 76 cb [2] 62 d0 [2] 6d ca [2] 73 d7 [2] 71 d6 [2] 6a d0 [2] 76 d7 [2] 6a f8 }

  condition:
    any of them
}