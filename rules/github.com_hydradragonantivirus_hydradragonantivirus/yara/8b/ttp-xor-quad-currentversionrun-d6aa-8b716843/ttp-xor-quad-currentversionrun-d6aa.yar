rule TTP_XOR_QUAD_CurrentVersionRun_d6aa {
  strings:
    $key_d6aa = { 85 c5 [2] a1 cb [2] 8a e7 [2] a4 c5 [2] b0 de [2] bf c4 [2] a1 d9 [2] a3 d8 [2] b8 de [2] a4 d9 [2] b8 f6 }

  condition:
    any of them
}