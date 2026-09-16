rule TTP_XOR_QUAD_CurrentVersionRun_ddd5 {
  strings:
    $key_ddd5 = { 8e ba [2] aa b4 [2] 81 98 [2] af ba [2] bb a1 [2] b4 bb [2] aa a6 [2] a8 a7 [2] b3 a1 [2] af a6 [2] b3 89 }

  condition:
    any of them
}