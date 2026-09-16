rule TTP_XOR_QUAD_CurrentVersionRun_d1a6 {
  strings:
    $key_d1a6 = { 82 c9 [2] a6 c7 [2] 8d eb [2] a3 c9 [2] b7 d2 [2] b8 c8 [2] a6 d5 [2] a4 d4 [2] bf d2 [2] a3 d5 [2] bf fa }

  condition:
    any of them
}