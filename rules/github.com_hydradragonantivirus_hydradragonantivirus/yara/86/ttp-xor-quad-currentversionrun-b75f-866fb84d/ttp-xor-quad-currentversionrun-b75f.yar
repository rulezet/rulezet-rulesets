rule TTP_XOR_QUAD_CurrentVersionRun_b75f {
  strings:
    $key_b75f = { e4 30 [2] c0 3e [2] eb 12 [2] c5 30 [2] d1 2b [2] de 31 [2] c0 2c [2] c2 2d [2] d9 2b [2] c5 2c [2] d9 03 }

  condition:
    any of them
}