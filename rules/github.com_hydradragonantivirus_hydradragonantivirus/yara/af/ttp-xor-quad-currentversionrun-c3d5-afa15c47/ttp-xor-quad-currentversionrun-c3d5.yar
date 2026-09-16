rule TTP_XOR_QUAD_CurrentVersionRun_c3d5 {
  strings:
    $key_c3d5 = { 90 ba [2] b4 b4 [2] 9f 98 [2] b1 ba [2] a5 a1 [2] aa bb [2] b4 a6 [2] b6 a7 [2] ad a1 [2] b1 a6 [2] ad 89 }

  condition:
    any of them
}