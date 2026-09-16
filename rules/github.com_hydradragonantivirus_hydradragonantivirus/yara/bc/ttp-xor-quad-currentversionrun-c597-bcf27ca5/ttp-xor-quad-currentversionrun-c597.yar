rule TTP_XOR_QUAD_CurrentVersionRun_c597 {
  strings:
    $key_c597 = { 96 f8 [2] b2 f6 [2] 99 da [2] b7 f8 [2] a3 e3 [2] ac f9 [2] b2 e4 [2] b0 e5 [2] ab e3 [2] b7 e4 [2] ab cb }

  condition:
    any of them
}