rule TTP_XOR_QUAD_CurrentVersionRun_d6a4 {
  strings:
    $key_d6a4 = { 85 cb [2] a1 c5 [2] 8a e9 [2] a4 cb [2] b0 d0 [2] bf ca [2] a1 d7 [2] a3 d6 [2] b8 d0 [2] a4 d7 [2] b8 f8 }

  condition:
    any of them
}