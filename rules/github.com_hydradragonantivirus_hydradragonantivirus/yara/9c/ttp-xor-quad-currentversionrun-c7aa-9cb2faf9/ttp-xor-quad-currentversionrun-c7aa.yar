rule TTP_XOR_QUAD_CurrentVersionRun_c7aa {
  strings:
    $key_c7aa = { 94 c5 [2] b0 cb [2] 9b e7 [2] b5 c5 [2] a1 de [2] ae c4 [2] b0 d9 [2] b2 d8 [2] a9 de [2] b5 d9 [2] a9 f6 }

  condition:
    any of them
}