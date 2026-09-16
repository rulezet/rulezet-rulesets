rule TTP_XOR_QUAD_CurrentVersionRun_66a5 {
  strings:
    $key_66a5 = { 35 ca [2] 11 c4 [2] 3a e8 [2] 14 ca [2] 00 d1 [2] 0f cb [2] 11 d6 [2] 13 d7 [2] 08 d1 [2] 14 d6 [2] 08 f9 }

  condition:
    any of them
}