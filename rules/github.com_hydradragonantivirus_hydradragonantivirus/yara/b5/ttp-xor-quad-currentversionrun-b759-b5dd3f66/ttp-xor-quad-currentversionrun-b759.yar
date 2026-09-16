rule TTP_XOR_QUAD_CurrentVersionRun_b759 {
  strings:
    $key_b759 = { e4 36 [2] c0 38 [2] eb 14 [2] c5 36 [2] d1 2d [2] de 37 [2] c0 2a [2] c2 2b [2] d9 2d [2] c5 2a [2] d9 05 }

  condition:
    any of them
}