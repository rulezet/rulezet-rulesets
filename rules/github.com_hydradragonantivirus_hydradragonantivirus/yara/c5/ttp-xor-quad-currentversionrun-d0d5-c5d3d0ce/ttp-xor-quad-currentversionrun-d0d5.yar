rule TTP_XOR_QUAD_CurrentVersionRun_d0d5 {
  strings:
    $key_d0d5 = { 83 ba [2] a7 b4 [2] 8c 98 [2] a2 ba [2] b6 a1 [2] b9 bb [2] a7 a6 [2] a5 a7 [2] be a1 [2] a2 a6 [2] be 89 }

  condition:
    any of them
}