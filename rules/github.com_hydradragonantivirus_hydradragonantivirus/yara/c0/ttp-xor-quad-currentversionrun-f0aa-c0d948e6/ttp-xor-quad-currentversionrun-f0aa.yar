rule TTP_XOR_QUAD_CurrentVersionRun_f0aa {
  strings:
    $key_f0aa = { a3 c5 [2] 87 cb [2] ac e7 [2] 82 c5 [2] 96 de [2] 99 c4 [2] 87 d9 [2] 85 d8 [2] 9e de [2] 82 d9 [2] 9e f6 }

  condition:
    any of them
}