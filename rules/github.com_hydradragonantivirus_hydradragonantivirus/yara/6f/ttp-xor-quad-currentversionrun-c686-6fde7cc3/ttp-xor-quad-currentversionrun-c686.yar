rule TTP_XOR_QUAD_CurrentVersionRun_c686 {
  strings:
    $key_c686 = { 95 e9 [2] b1 e7 [2] 9a cb [2] b4 e9 [2] a0 f2 [2] af e8 [2] b1 f5 [2] b3 f4 [2] a8 f2 [2] b4 f5 [2] a8 da }

  condition:
    any of them
}