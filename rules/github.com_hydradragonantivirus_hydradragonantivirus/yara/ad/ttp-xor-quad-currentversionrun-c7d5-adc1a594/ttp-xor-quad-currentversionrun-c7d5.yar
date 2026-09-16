rule TTP_XOR_QUAD_CurrentVersionRun_c7d5 {
  strings:
    $key_c7d5 = { 94 ba [2] b0 b4 [2] 9b 98 [2] b5 ba [2] a1 a1 [2] ae bb [2] b0 a6 [2] b2 a7 [2] a9 a1 [2] b5 a6 [2] a9 89 }

  condition:
    any of them
}