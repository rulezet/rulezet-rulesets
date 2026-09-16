rule TTP_XOR_QUAD_CurrentVersionRun_d6b8 {
  strings:
    $key_d6b8 = { 85 d7 [2] a1 d9 [2] 8a f5 [2] a4 d7 [2] b0 cc [2] bf d6 [2] a1 cb [2] a3 ca [2] b8 cc [2] a4 cb [2] b8 e4 }

  condition:
    any of them
}