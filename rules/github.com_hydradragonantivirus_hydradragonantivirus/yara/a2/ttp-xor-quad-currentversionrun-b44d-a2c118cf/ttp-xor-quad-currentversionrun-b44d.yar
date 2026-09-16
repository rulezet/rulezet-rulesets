rule TTP_XOR_QUAD_CurrentVersionRun_b44d {
  strings:
    $key_b44d = { e7 22 [2] c3 2c [2] e8 00 [2] c6 22 [2] d2 39 [2] dd 23 [2] c3 3e [2] c1 3f [2] da 39 [2] c6 3e [2] da 11 }

  condition:
    any of them
}