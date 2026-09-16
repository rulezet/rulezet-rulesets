rule TTP_XOR_QUAD_CurrentVersionRun_10a4 {
  strings:
    $key_10a4 = { 43 cb [2] 67 c5 [2] 4c e9 [2] 62 cb [2] 76 d0 [2] 79 ca [2] 67 d7 [2] 65 d6 [2] 7e d0 [2] 62 d7 [2] 7e f8 }

  condition:
    any of them
}