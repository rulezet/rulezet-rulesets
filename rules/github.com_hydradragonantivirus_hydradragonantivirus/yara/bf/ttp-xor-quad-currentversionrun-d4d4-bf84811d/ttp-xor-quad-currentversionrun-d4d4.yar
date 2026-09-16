rule TTP_XOR_QUAD_CurrentVersionRun_d4d4 {
  strings:
    $key_d4d4 = { 87 bb [2] a3 b5 [2] 88 99 [2] a6 bb [2] b2 a0 [2] bd ba [2] a3 a7 [2] a1 a6 [2] ba a0 [2] a6 a7 [2] ba 88 }

  condition:
    any of them
}