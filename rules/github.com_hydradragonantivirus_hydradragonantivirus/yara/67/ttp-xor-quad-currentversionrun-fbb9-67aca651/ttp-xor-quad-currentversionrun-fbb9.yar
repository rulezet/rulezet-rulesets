rule TTP_XOR_QUAD_CurrentVersionRun_fbb9 {
  strings:
    $key_fbb9 = { a8 d6 [2] 8c d8 [2] a7 f4 [2] 89 d6 [2] 9d cd [2] 92 d7 [2] 8c ca [2] 8e cb [2] 95 cd [2] 89 ca [2] 95 e5 }

  condition:
    any of them
}