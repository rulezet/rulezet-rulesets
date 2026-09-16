rule TTP_XOR_QUAD_CurrentVersionRun_d1d4 {
  strings:
    $key_d1d4 = { 82 bb [2] a6 b5 [2] 8d 99 [2] a3 bb [2] b7 a0 [2] b8 ba [2] a6 a7 [2] a4 a6 [2] bf a0 [2] a3 a7 [2] bf 88 }

  condition:
    any of them
}