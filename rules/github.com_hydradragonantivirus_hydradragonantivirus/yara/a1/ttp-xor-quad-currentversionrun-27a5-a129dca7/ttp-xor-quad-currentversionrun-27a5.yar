rule TTP_XOR_QUAD_CurrentVersionRun_27a5 {
  strings:
    $key_27a5 = { 74 ca [2] 50 c4 [2] 7b e8 [2] 55 ca [2] 41 d1 [2] 4e cb [2] 50 d6 [2] 52 d7 [2] 49 d1 [2] 55 d6 [2] 49 f9 }

  condition:
    any of them
}