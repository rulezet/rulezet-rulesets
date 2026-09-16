rule TTP_XOR_QUAD_CurrentVersionRun_d196 {
  strings:
    $key_d196 = { 82 f9 [2] a6 f7 [2] 8d db [2] a3 f9 [2] b7 e2 [2] b8 f8 [2] a6 e5 [2] a4 e4 [2] bf e2 [2] a3 e5 [2] bf ca }

  condition:
    any of them
}