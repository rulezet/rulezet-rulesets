rule TTP_XOR_QUAD_CurrentVersionRun_b45c {
  strings:
    $key_b45c = { e7 33 [2] c3 3d [2] e8 11 [2] c6 33 [2] d2 28 [2] dd 32 [2] c3 2f [2] c1 2e [2] da 28 [2] c6 2f [2] da 00 }

  condition:
    any of them
}