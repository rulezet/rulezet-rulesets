rule TTP_XOR_QUAD_CurrentVersionRun_d5b4 {
  strings:
    $key_d5b4 = { 86 db [2] a2 d5 [2] 89 f9 [2] a7 db [2] b3 c0 [2] bc da [2] a2 c7 [2] a0 c6 [2] bb c0 [2] a7 c7 [2] bb e8 }

  condition:
    any of them
}