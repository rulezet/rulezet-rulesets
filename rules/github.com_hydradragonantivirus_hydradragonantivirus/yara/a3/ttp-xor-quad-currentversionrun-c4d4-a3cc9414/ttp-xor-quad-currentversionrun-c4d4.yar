rule TTP_XOR_QUAD_CurrentVersionRun_c4d4 {
  strings:
    $key_c4d4 = { 97 bb [2] b3 b5 [2] 98 99 [2] b6 bb [2] a2 a0 [2] ad ba [2] b3 a7 [2] b1 a6 [2] aa a0 [2] b6 a7 [2] aa 88 }

  condition:
    any of them
}