rule TTP_XOR_QUAD_CurrentVersionRun_b3fb {
  strings:
    $key_b3fb = { e0 94 [2] c4 9a [2] ef b6 [2] c1 94 [2] d5 8f [2] da 95 [2] c4 88 [2] c6 89 [2] dd 8f [2] c1 88 [2] dd a7 }

  condition:
    any of them
}