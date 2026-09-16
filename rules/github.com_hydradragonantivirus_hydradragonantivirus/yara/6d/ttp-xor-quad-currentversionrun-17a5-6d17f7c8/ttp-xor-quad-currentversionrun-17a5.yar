rule TTP_XOR_QUAD_CurrentVersionRun_17a5 {
  strings:
    $key_17a5 = { 44 ca [2] 60 c4 [2] 4b e8 [2] 65 ca [2] 71 d1 [2] 7e cb [2] 60 d6 [2] 62 d7 [2] 79 d1 [2] 65 d6 [2] 79 f9 }

  condition:
    any of them
}