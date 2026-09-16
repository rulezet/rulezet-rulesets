rule TTP_XOR_QUAD_CurrentVersionRun_dfd5 {
  strings:
    $key_dfd5 = { 8c ba [2] a8 b4 [2] 83 98 [2] ad ba [2] b9 a1 [2] b6 bb [2] a8 a6 [2] aa a7 [2] b1 a1 [2] ad a6 [2] b1 89 }

  condition:
    any of them
}