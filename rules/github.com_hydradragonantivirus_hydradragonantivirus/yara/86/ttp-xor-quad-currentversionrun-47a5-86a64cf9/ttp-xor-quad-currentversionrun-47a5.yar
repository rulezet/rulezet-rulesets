rule TTP_XOR_QUAD_CurrentVersionRun_47a5 {
  strings:
    $key_47a5 = { 14 ca [2] 30 c4 [2] 1b e8 [2] 35 ca [2] 21 d1 [2] 2e cb [2] 30 d6 [2] 32 d7 [2] 29 d1 [2] 35 d6 [2] 29 f9 }

  condition:
    any of them
}