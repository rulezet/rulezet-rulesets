rule TTP_XOR_QUAD_CurrentVersionRun_b470 {
  strings:
    $key_b470 = { e7 1f [2] c3 11 [2] e8 3d [2] c6 1f [2] d2 04 [2] dd 1e [2] c3 03 [2] c1 02 [2] da 04 [2] c6 03 [2] da 2c }

  condition:
    any of them
}