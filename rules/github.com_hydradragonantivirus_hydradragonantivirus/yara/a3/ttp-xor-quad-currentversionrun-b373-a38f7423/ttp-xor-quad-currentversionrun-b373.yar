rule TTP_XOR_QUAD_CurrentVersionRun_b373 {
  strings:
    $key_b373 = { e0 1c [2] c4 12 [2] ef 3e [2] c1 1c [2] d5 07 [2] da 1d [2] c4 00 [2] c6 01 [2] dd 07 [2] c1 00 [2] dd 2f }

  condition:
    any of them
}