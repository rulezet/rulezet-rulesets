rule TTP_XOR_QUAD_CurrentVersionRun_1da4 {
  strings:
    $key_1da4 = { 4e cb [2] 6a c5 [2] 41 e9 [2] 6f cb [2] 7b d0 [2] 74 ca [2] 6a d7 [2] 68 d6 [2] 73 d0 [2] 6f d7 [2] 73 f8 }

  condition:
    any of them
}