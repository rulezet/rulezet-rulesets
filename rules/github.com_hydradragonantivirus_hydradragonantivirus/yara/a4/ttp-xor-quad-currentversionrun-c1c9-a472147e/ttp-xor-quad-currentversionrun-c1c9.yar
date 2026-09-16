rule TTP_XOR_QUAD_CurrentVersionRun_c1c9 {
  strings:
    $key_c1c9 = { 92 a6 [2] b6 a8 [2] 9d 84 [2] b3 a6 [2] a7 bd [2] a8 a7 [2] b6 ba [2] b4 bb [2] af bd [2] b3 ba [2] af 95 }

  condition:
    any of them
}