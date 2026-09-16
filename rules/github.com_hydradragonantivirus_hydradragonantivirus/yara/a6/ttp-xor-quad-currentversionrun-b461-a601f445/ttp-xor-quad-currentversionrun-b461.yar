rule TTP_XOR_QUAD_CurrentVersionRun_b461 {
  strings:
    $key_b461 = { e7 0e [2] c3 00 [2] e8 2c [2] c6 0e [2] d2 15 [2] dd 0f [2] c3 12 [2] c1 13 [2] da 15 [2] c6 12 [2] da 3d }

  condition:
    any of them
}