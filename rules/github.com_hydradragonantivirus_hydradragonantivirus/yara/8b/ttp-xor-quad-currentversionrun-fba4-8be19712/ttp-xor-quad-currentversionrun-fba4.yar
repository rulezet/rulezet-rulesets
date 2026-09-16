rule TTP_XOR_QUAD_CurrentVersionRun_fba4 {
  strings:
    $key_fba4 = { a8 cb [2] 8c c5 [2] a7 e9 [2] 89 cb [2] 9d d0 [2] 92 ca [2] 8c d7 [2] 8e d6 [2] 95 d0 [2] 89 d7 [2] 95 f8 }

  condition:
    any of them
}