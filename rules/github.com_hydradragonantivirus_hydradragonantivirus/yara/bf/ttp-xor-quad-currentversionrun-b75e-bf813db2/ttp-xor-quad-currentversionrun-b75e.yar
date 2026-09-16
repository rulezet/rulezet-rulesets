rule TTP_XOR_QUAD_CurrentVersionRun_b75e {
  strings:
    $key_b75e = { e4 31 [2] c0 3f [2] eb 13 [2] c5 31 [2] d1 2a [2] de 30 [2] c0 2d [2] c2 2c [2] d9 2a [2] c5 2d [2] d9 02 }

  condition:
    any of them
}