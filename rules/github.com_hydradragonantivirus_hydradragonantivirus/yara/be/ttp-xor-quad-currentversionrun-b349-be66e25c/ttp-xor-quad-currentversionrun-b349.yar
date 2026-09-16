rule TTP_XOR_QUAD_CurrentVersionRun_b349 {
  strings:
    $key_b349 = { e0 26 [2] c4 28 [2] ef 04 [2] c1 26 [2] d5 3d [2] da 27 [2] c4 3a [2] c6 3b [2] dd 3d [2] c1 3a [2] dd 15 }

  condition:
    any of them
}