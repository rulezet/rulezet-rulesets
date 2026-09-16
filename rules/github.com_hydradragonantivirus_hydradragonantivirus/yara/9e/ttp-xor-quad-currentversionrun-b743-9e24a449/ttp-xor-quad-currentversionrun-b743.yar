rule TTP_XOR_QUAD_CurrentVersionRun_b743 {
  strings:
    $key_b743 = { e4 2c [2] c0 22 [2] eb 0e [2] c5 2c [2] d1 37 [2] de 2d [2] c0 30 [2] c2 31 [2] d9 37 [2] c5 30 [2] d9 1f }

  condition:
    any of them
}