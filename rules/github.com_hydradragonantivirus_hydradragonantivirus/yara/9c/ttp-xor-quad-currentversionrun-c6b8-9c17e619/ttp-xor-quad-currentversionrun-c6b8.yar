rule TTP_XOR_QUAD_CurrentVersionRun_c6b8 {
  strings:
    $key_c6b8 = { 95 d7 [2] b1 d9 [2] 9a f5 [2] b4 d7 [2] a0 cc [2] af d6 [2] b1 cb [2] b3 ca [2] a8 cc [2] b4 cb [2] a8 e4 }

  condition:
    any of them
}