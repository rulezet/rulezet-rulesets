rule TTP_XOR_QUAD_CurrentVersionRun_77a4 {
  strings:
    $key_77a4 = { 24 cb [2] 00 c5 [2] 2b e9 [2] 05 cb [2] 11 d0 [2] 1e ca [2] 00 d7 [2] 02 d6 [2] 19 d0 [2] 05 d7 [2] 19 f8 }

  condition:
    any of them
}