rule TTP_XOR_QUAD_CurrentVersionRun_c7b7 {
  strings:
    $key_c7b7 = { 94 d8 [2] b0 d6 [2] 9b fa [2] b5 d8 [2] a1 c3 [2] ae d9 [2] b0 c4 [2] b2 c5 [2] a9 c3 [2] b5 c4 [2] a9 eb }

  condition:
    any of them
}