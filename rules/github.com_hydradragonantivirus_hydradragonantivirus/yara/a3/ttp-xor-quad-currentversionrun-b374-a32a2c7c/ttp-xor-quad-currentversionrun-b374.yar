rule TTP_XOR_QUAD_CurrentVersionRun_b374 {
  strings:
    $key_b374 = { e0 1b [2] c4 15 [2] ef 39 [2] c1 1b [2] d5 00 [2] da 1a [2] c4 07 [2] c6 06 [2] dd 00 [2] c1 07 [2] dd 28 }

  condition:
    any of them
}