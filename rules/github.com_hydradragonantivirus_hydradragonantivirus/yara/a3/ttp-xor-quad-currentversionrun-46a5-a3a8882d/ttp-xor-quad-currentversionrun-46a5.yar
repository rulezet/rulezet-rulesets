rule TTP_XOR_QUAD_CurrentVersionRun_46a5 {
  strings:
    $key_46a5 = { 15 ca [2] 31 c4 [2] 1a e8 [2] 34 ca [2] 20 d1 [2] 2f cb [2] 31 d6 [2] 33 d7 [2] 28 d1 [2] 34 d6 [2] 28 f9 }

  condition:
    any of them
}