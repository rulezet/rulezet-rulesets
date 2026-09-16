rule TTP_XOR_QUAD_CurrentVersionRun_c1d4 {
  strings:
    $key_c1d4 = { 92 bb [2] b6 b5 [2] 9d 99 [2] b3 bb [2] a7 a0 [2] a8 ba [2] b6 a7 [2] b4 a6 [2] af a0 [2] b3 a7 [2] af 88 }

  condition:
    any of them
}