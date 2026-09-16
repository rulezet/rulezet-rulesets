rule TTP_XOR_QUAD_CurrentVersionRun_c7a4 {
  strings:
    $key_c7a4 = { 94 cb [2] b0 c5 [2] 9b e9 [2] b5 cb [2] a1 d0 [2] ae ca [2] b0 d7 [2] b2 d6 [2] a9 d0 [2] b5 d7 [2] a9 f8 }

  condition:
    any of them
}