rule TTP_XOR_QUAD_CurrentVersionRun_25b8 {
  strings:
    $key_25b8 = { 76 d7 [2] 52 d9 [2] 79 f5 [2] 57 d7 [2] 43 cc [2] 4c d6 [2] 52 cb [2] 50 ca [2] 4b cc [2] 57 cb [2] 4b e4 }

  condition:
    any of them
}