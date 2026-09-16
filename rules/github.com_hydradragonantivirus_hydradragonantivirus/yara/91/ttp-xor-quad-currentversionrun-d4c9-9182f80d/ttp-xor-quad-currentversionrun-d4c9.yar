rule TTP_XOR_QUAD_CurrentVersionRun_d4c9 {
  strings:
    $key_d4c9 = { 87 a6 [2] a3 a8 [2] 88 84 [2] a6 a6 [2] b2 bd [2] bd a7 [2] a3 ba [2] a1 bb [2] ba bd [2] a6 ba [2] ba 95 }

  condition:
    any of them
}