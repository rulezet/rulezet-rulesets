rule TTP_XOR_QUAD_CurrentVersionRun_c6d4 {
  strings:
    $key_c6d4 = { 95 bb [2] b1 b5 [2] 9a 99 [2] b4 bb [2] a0 a0 [2] af ba [2] b1 a7 [2] b3 a6 [2] a8 a0 [2] b4 a7 [2] a8 88 }

  condition:
    any of them
}