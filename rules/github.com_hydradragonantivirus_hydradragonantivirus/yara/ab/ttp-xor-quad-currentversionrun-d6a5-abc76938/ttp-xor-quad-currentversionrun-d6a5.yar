rule TTP_XOR_QUAD_CurrentVersionRun_d6a5 {
  strings:
    $key_d6a5 = { 85 ca [2] a1 c4 [2] 8a e8 [2] a4 ca [2] b0 d1 [2] bf cb [2] a1 d6 [2] a3 d7 [2] b8 d1 [2] a4 d6 [2] b8 f9 }

  condition:
    any of them
}