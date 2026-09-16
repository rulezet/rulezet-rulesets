rule TTP_XOR_QUAD_CurrentVersionRun_b3c8 {
  strings:
    $key_b3c8 = { e0 a7 [2] c4 a9 [2] ef 85 [2] c1 a7 [2] d5 bc [2] da a6 [2] c4 bb [2] c6 ba [2] dd bc [2] c1 bb [2] dd 94 }

  condition:
    any of them
}