rule TTP_XOR_QUAD_CurrentVersionRun_b4fb {
  strings:
    $key_b4fb = { e7 94 [2] c3 9a [2] e8 b6 [2] c6 94 [2] d2 8f [2] dd 95 [2] c3 88 [2] c1 89 [2] da 8f [2] c6 88 [2] da a7 }

  condition:
    any of them
}