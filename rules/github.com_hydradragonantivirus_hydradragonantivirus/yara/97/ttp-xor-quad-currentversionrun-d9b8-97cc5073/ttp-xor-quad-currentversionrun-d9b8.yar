rule TTP_XOR_QUAD_CurrentVersionRun_d9b8 {
  strings:
    $key_d9b8 = { 8a d7 [2] ae d9 [2] 85 f5 [2] ab d7 [2] bf cc [2] b0 d6 [2] ae cb [2] ac ca [2] b7 cc [2] ab cb [2] b7 e4 }

  condition:
    any of them
}