rule TTP_XOR_QUAD_CurrentVersionRun_fbb8 {
  strings:
    $key_fbb8 = { a8 d7 [2] 8c d9 [2] a7 f5 [2] 89 d7 [2] 9d cc [2] 92 d6 [2] 8c cb [2] 8e ca [2] 95 cc [2] 89 cb [2] 95 e4 }

  condition:
    any of them
}