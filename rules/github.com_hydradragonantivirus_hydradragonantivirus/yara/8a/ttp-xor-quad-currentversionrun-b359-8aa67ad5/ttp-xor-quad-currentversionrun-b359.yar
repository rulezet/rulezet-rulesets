rule TTP_XOR_QUAD_CurrentVersionRun_b359 {
  strings:
    $key_b359 = { e0 36 [2] c4 38 [2] ef 14 [2] c1 36 [2] d5 2d [2] da 37 [2] c4 2a [2] c6 2b [2] dd 2d [2] c1 2a [2] dd 05 }

  condition:
    any of them
}