rule TTP_XOR_QUAD_CurrentVersionRun_f0b8 {
  strings:
    $key_f0b8 = { a3 d7 [2] 87 d9 [2] ac f5 [2] 82 d7 [2] 96 cc [2] 99 d6 [2] 87 cb [2] 85 ca [2] 9e cc [2] 82 cb [2] 9e e4 }

  condition:
    any of them
}