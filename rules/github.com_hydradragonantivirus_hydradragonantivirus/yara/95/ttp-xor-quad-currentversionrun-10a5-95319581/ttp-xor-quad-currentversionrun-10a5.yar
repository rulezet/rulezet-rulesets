rule TTP_XOR_QUAD_CurrentVersionRun_10a5 {
  strings:
    $key_10a5 = { 43 ca [2] 67 c4 [2] 4c e8 [2] 62 ca [2] 76 d1 [2] 79 cb [2] 67 d6 [2] 65 d7 [2] 7e d1 [2] 62 d6 [2] 7e f9 }

  condition:
    any of them
}