rule TTP_XOR_QUAD_CurrentVersionRun_c4c9 {
  strings:
    $key_c4c9 = { 97 a6 [2] b3 a8 [2] 98 84 [2] b6 a6 [2] a2 bd [2] ad a7 [2] b3 ba [2] b1 bb [2] aa bd [2] b6 ba [2] aa 95 }

  condition:
    any of them
}