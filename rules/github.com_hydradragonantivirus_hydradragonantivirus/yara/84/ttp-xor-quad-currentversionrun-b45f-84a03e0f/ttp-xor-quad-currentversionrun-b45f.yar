rule TTP_XOR_QUAD_CurrentVersionRun_b45f {
  strings:
    $key_b45f = { e7 30 [2] c3 3e [2] e8 12 [2] c6 30 [2] d2 2b [2] dd 31 [2] c3 2c [2] c1 2d [2] da 2b [2] c6 2c [2] da 03 }

  condition:
    any of them
}