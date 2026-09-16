rule TTP_XOR_QUAD_CurrentVersionRun_b379 {
  strings:
    $key_b379 = { e0 16 [2] c4 18 [2] ef 34 [2] c1 16 [2] d5 0d [2] da 17 [2] c4 0a [2] c6 0b [2] dd 0d [2] c1 0a [2] dd 25 }

  condition:
    any of them
}