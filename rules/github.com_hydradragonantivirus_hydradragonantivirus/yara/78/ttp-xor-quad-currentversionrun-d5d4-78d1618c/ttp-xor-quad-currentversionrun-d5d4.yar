rule TTP_XOR_QUAD_CurrentVersionRun_d5d4 {
  strings:
    $key_d5d4 = { 86 bb [2] a2 b5 [2] 89 99 [2] a7 bb [2] b3 a0 [2] bc ba [2] a2 a7 [2] a0 a6 [2] bb a0 [2] a7 a7 [2] bb 88 }

  condition:
    any of them
}