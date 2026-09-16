rule TTP_XOR_QUAD_CurrentVersionRun_c6c9 {
  strings:
    $key_c6c9 = { 95 a6 [2] b1 a8 [2] 9a 84 [2] b4 a6 [2] a0 bd [2] af a7 [2] b1 ba [2] b3 bb [2] a8 bd [2] b4 ba [2] a8 95 }

  condition:
    any of them
}