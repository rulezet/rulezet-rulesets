rule TTP_XOR_QUAD_CurrentVersionRun_c6b7 {
  strings:
    $key_c6b7 = { 95 d8 [2] b1 d6 [2] 9a fa [2] b4 d8 [2] a0 c3 [2] af d9 [2] b1 c4 [2] b3 c5 [2] a8 c3 [2] b4 c4 [2] a8 eb }

  condition:
    any of them
}