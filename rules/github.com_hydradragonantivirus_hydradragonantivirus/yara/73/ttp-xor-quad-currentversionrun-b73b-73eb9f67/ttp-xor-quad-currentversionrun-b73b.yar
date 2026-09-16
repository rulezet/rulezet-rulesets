rule TTP_XOR_QUAD_CurrentVersionRun_b73b {
  strings:
    $key_b73b = { e4 54 [2] c0 5a [2] eb 76 [2] c5 54 [2] d1 4f [2] de 55 [2] c0 48 [2] c2 49 [2] d9 4f [2] c5 48 [2] d9 67 }

  condition:
    any of them
}