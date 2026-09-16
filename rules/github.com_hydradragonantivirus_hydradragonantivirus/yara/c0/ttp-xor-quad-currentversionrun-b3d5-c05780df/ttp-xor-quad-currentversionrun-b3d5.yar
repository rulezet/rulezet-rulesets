rule TTP_XOR_QUAD_CurrentVersionRun_b3d5 {
  strings:
    $key_b3d5 = { e0 ba [2] c4 b4 [2] ef 98 [2] c1 ba [2] d5 a1 [2] da bb [2] c4 a6 [2] c6 a7 [2] dd a1 [2] c1 a6 [2] dd 89 }

  condition:
    any of them
}