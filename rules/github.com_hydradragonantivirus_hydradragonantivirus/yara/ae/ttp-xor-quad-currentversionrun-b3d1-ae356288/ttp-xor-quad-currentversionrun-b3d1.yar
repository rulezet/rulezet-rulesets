rule TTP_XOR_QUAD_CurrentVersionRun_b3d1 {
  strings:
    $key_b3d1 = { e0 be [2] c4 b0 [2] ef 9c [2] c1 be [2] d5 a5 [2] da bf [2] c4 a2 [2] c6 a3 [2] dd a5 [2] c1 a2 [2] dd 8d }

  condition:
    any of them
}