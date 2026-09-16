rule TTP_XOR_QUAD_CurrentVersionRun_c6a4 {
  strings:
    $key_c6a4 = { 95 cb [2] b1 c5 [2] 9a e9 [2] b4 cb [2] a0 d0 [2] af ca [2] b1 d7 [2] b3 d6 [2] a8 d0 [2] b4 d7 [2] a8 f8 }

  condition:
    any of them
}