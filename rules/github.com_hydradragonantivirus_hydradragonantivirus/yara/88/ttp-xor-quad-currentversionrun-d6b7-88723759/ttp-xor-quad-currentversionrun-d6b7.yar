rule TTP_XOR_QUAD_CurrentVersionRun_d6b7 {
  strings:
    $key_d6b7 = { 85 d8 [2] a1 d6 [2] 8a fa [2] a4 d8 [2] b0 c3 [2] bf d9 [2] a1 c4 [2] a3 c5 [2] b8 c3 [2] a4 c4 [2] b8 eb }

  condition:
    any of them
}