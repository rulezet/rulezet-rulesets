rule TTP_XOR_QUAD_CurrentVersionRun_25b9 {
  strings:
    $key_25b9 = { 76 d6 [2] 52 d8 [2] 79 f4 [2] 57 d6 [2] 43 cd [2] 4c d7 [2] 52 ca [2] 50 cb [2] 4b cd [2] 57 ca [2] 4b e5 }

  condition:
    any of them
}