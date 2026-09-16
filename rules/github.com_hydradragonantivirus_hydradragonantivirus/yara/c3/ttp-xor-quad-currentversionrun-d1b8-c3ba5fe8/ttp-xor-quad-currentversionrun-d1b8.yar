rule TTP_XOR_QUAD_CurrentVersionRun_d1b8 {
  strings:
    $key_d1b8 = { 82 d7 [2] a6 d9 [2] 8d f5 [2] a3 d7 [2] b7 cc [2] b8 d6 [2] a6 cb [2] a4 ca [2] bf cc [2] a3 cb [2] bf e4 }

  condition:
    any of them
}