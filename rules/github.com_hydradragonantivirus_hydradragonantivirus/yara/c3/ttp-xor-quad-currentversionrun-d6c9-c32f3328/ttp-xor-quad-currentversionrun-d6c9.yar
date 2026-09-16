rule TTP_XOR_QUAD_CurrentVersionRun_d6c9 {
  strings:
    $key_d6c9 = { 85 a6 [2] a1 a8 [2] 8a 84 [2] a4 a6 [2] b0 bd [2] bf a7 [2] a1 ba [2] a3 bb [2] b8 bd [2] a4 ba [2] b8 95 }

  condition:
    any of them
}