rule TTP_XOR_QUAD_CurrentVersionRun_20a4 {
  strings:
    $key_20a4 = { 73 cb [2] 57 c5 [2] 7c e9 [2] 52 cb [2] 46 d0 [2] 49 ca [2] 57 d7 [2] 55 d6 [2] 4e d0 [2] 52 d7 [2] 4e f8 }

  condition:
    any of them
}