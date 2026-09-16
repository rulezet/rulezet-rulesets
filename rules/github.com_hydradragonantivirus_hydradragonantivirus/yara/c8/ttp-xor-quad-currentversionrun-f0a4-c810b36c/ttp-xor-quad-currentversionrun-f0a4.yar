rule TTP_XOR_QUAD_CurrentVersionRun_f0a4 {
  strings:
    $key_f0a4 = { a3 cb [2] 87 c5 [2] ac e9 [2] 82 cb [2] 96 d0 [2] 99 ca [2] 87 d7 [2] 85 d6 [2] 9e d0 [2] 82 d7 [2] 9e f8 }

  condition:
    any of them
}