rule TTP_XOR_QUAD_CurrentVersionRun_77a5 {
  strings:
    $key_77a5 = { 24 ca [2] 00 c4 [2] 2b e8 [2] 05 ca [2] 11 d1 [2] 1e cb [2] 00 d6 [2] 02 d7 [2] 19 d1 [2] 05 d6 [2] 19 f9 }

  condition:
    any of them
}