rule TTP_XOR_QUAD_CurrentVersionRun_d5b5 {
  strings:
    $key_d5b5 = { 86 da [2] a2 d4 [2] 89 f8 [2] a7 da [2] b3 c1 [2] bc db [2] a2 c6 [2] a0 c7 [2] bb c1 [2] a7 c6 [2] bb e9 }

  condition:
    any of them
}