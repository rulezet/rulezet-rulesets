rule TTP_XOR_QUAD_CurrentVersionRun_c3c9 {
  strings:
    $key_c3c9 = { 90 a6 [2] b4 a8 [2] 9f 84 [2] b1 a6 [2] a5 bd [2] aa a7 [2] b4 ba [2] b6 bb [2] ad bd [2] b1 ba [2] ad 95 }

  condition:
    any of them
}