rule TTP_XOR_QUAD_CurrentVersionRun_c197 {
  strings:
    $key_c197 = { 92 f8 [2] b6 f6 [2] 9d da [2] b3 f8 [2] a7 e3 [2] a8 f9 [2] b6 e4 [2] b4 e5 [2] af e3 [2] b3 e4 [2] af cb }

  condition:
    any of them
}