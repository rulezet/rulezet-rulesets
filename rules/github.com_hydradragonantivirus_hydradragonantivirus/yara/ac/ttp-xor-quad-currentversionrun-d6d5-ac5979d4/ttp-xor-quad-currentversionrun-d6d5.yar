rule TTP_XOR_QUAD_CurrentVersionRun_d6d5 {
  strings:
    $key_d6d5 = { 85 ba [2] a1 b4 [2] 8a 98 [2] a4 ba [2] b0 a1 [2] bf bb [2] a1 a6 [2] a3 a7 [2] b8 a1 [2] a4 a6 [2] b8 89 }

  condition:
    any of them
}