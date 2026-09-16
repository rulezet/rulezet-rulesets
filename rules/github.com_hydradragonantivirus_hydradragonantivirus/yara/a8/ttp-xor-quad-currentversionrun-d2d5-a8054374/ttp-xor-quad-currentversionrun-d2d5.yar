rule TTP_XOR_QUAD_CurrentVersionRun_d2d5 {
  strings:
    $key_d2d5 = { 81 ba [2] a5 b4 [2] 8e 98 [2] a0 ba [2] b4 a1 [2] bb bb [2] a5 a6 [2] a7 a7 [2] bc a1 [2] a0 a6 [2] bc 89 }

  condition:
    any of them
}