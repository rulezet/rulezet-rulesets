rule TTP_XOR_QUAD_CurrentVersionRun_c3c8 {
  strings:
    $key_c3c8 = { 90 a7 [2] b4 a9 [2] 9f 85 [2] b1 a7 [2] a5 bc [2] aa a6 [2] b4 bb [2] b6 ba [2] ad bc [2] b1 bb [2] ad 94 }

  condition:
    any of them
}