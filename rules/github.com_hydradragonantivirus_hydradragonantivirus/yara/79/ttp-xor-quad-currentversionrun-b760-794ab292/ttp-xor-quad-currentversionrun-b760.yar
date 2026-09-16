rule TTP_XOR_QUAD_CurrentVersionRun_b760 {
  strings:
    $key_b760 = { e4 0f [2] c0 01 [2] eb 2d [2] c5 0f [2] d1 14 [2] de 0e [2] c0 13 [2] c2 12 [2] d9 14 [2] c5 13 [2] d9 3c }

  condition:
    any of them
}