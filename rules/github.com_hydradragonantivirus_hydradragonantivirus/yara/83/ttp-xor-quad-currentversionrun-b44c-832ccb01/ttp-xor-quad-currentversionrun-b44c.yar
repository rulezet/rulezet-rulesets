rule TTP_XOR_QUAD_CurrentVersionRun_b44c {
  strings:
    $key_b44c = { e7 23 [2] c3 2d [2] e8 01 [2] c6 23 [2] d2 38 [2] dd 22 [2] c3 3f [2] c1 3e [2] da 38 [2] c6 3f [2] da 10 }

  condition:
    any of them
}