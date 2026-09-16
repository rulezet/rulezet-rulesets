rule TTP_XOR_QUAD_CurrentVersionRun_b7fb {
  strings:
    $key_b7fb = { e4 94 [2] c0 9a [2] eb b6 [2] c5 94 [2] d1 8f [2] de 95 [2] c0 88 [2] c2 89 [2] d9 8f [2] c5 88 [2] d9 a7 }

  condition:
    any of them
}