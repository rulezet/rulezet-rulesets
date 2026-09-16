rule TTP_XOR_QUAD_CurrentVersionRun_c0d5 {
  strings:
    $key_c0d5 = { 93 ba [2] b7 b4 [2] 9c 98 [2] b2 ba [2] a6 a1 [2] a9 bb [2] b7 a6 [2] b5 a7 [2] ae a1 [2] b2 a6 [2] ae 89 }

  condition:
    any of them
}