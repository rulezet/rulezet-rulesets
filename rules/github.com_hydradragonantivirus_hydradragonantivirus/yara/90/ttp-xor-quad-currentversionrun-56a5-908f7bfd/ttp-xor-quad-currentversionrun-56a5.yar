rule TTP_XOR_QUAD_CurrentVersionRun_56a5 {
  strings:
    $key_56a5 = { 05 ca [2] 21 c4 [2] 0a e8 [2] 24 ca [2] 30 d1 [2] 3f cb [2] 21 d6 [2] 23 d7 [2] 38 d1 [2] 24 d6 [2] 38 f9 }

  condition:
    any of them
}