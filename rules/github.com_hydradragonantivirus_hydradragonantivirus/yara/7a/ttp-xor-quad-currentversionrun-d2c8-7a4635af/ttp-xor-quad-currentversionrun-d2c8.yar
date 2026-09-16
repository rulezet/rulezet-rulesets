rule TTP_XOR_QUAD_CurrentVersionRun_d2c8 {
  strings:
    $key_d2c8 = { 81 a7 [2] a5 a9 [2] 8e 85 [2] a0 a7 [2] b4 bc [2] bb a6 [2] a5 bb [2] a7 ba [2] bc bc [2] a0 bb [2] bc 94 }

  condition:
    any of them
}