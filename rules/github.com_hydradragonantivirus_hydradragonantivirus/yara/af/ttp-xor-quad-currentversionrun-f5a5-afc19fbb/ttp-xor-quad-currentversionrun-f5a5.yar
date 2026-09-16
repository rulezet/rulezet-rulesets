rule TTP_XOR_QUAD_CurrentVersionRun_f5a5 {
  strings:
    $key_f5a5 = { a6 ca [2] 82 c4 [2] a9 e8 [2] 87 ca [2] 93 d1 [2] 9c cb [2] 82 d6 [2] 80 d7 [2] 9b d1 [2] 87 d6 [2] 9b f9 }

  condition:
    any of them
}