rule TTP_XOR_QUAD_CurrentVersionRun_b343 {
  strings:
    $key_b343 = { e0 2c [2] c4 22 [2] ef 0e [2] c1 2c [2] d5 37 [2] da 2d [2] c4 30 [2] c6 31 [2] dd 37 [2] c1 30 [2] dd 1f }

  condition:
    any of them
}