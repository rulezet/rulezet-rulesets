rule TTP_XOR_QUAD_CurrentVersionRun_c1b8 {
  strings:
    $key_c1b8 = { 92 d7 [2] b6 d9 [2] 9d f5 [2] b3 d7 [2] a7 cc [2] a8 d6 [2] b6 cb [2] b4 ca [2] af cc [2] b3 cb [2] af e4 }

  condition:
    any of them
}