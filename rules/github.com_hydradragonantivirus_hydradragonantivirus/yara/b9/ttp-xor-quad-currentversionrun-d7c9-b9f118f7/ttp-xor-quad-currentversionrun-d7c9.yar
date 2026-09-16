rule TTP_XOR_QUAD_CurrentVersionRun_d7c9 {
  strings:
    $key_d7c9 = { 84 a6 [2] a0 a8 [2] 8b 84 [2] a5 a6 [2] b1 bd [2] be a7 [2] a0 ba [2] a2 bb [2] b9 bd [2] a5 ba [2] b9 95 }

  condition:
    any of them
}