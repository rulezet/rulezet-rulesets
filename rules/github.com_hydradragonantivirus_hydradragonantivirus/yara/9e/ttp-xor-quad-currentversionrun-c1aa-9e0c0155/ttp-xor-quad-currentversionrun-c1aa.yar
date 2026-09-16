rule TTP_XOR_QUAD_CurrentVersionRun_c1aa {
  strings:
    $key_c1aa = { 92 c5 [2] b6 cb [2] 9d e7 [2] b3 c5 [2] a7 de [2] a8 c4 [2] b6 d9 [2] b4 d8 [2] af de [2] b3 d9 [2] af f6 }

  condition:
    any of them
}