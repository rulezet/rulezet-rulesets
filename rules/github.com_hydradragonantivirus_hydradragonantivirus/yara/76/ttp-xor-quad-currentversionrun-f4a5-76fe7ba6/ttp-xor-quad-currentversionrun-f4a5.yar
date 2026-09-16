rule TTP_XOR_QUAD_CurrentVersionRun_f4a5 {
  strings:
    $key_f4a5 = { a7 ca [2] 83 c4 [2] a8 e8 [2] 86 ca [2] 92 d1 [2] 9d cb [2] 83 d6 [2] 81 d7 [2] 9a d1 [2] 86 d6 [2] 9a f9 }

  condition:
    any of them
}