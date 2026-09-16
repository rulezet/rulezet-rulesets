rule TTP_XOR_QUAD_CurrentVersionRun_b460 {
  strings:
    $key_b460 = { e7 0f [2] c3 01 [2] e8 2d [2] c6 0f [2] d2 14 [2] dd 0e [2] c3 13 [2] c1 12 [2] da 14 [2] c6 13 [2] da 3c }

  condition:
    any of them
}