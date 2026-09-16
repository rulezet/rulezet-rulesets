rule TTP_XOR_QUAD_CurrentVersionRun_60a5 {
  strings:
    $key_60a5 = { 33 ca [2] 17 c4 [2] 3c e8 [2] 12 ca [2] 06 d1 [2] 09 cb [2] 17 d6 [2] 15 d7 [2] 0e d1 [2] 12 d6 [2] 0e f9 }

  condition:
    any of them
}