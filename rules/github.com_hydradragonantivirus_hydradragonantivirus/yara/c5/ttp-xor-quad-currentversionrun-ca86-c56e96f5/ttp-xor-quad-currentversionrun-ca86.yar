rule TTP_XOR_QUAD_CurrentVersionRun_ca86 {
  strings:
    $key_ca86 = { 99 e9 [2] bd e7 [2] 96 cb [2] b8 e9 [2] ac f2 [2] a3 e8 [2] bd f5 [2] bf f4 [2] a4 f2 [2] b8 f5 [2] a4 da }

  condition:
    any of them
}