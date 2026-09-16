rule TTP_XOR_QUAD_CurrentVersionRun_b70b {
  strings:
    $key_b70b = { e4 64 [2] c0 6a [2] eb 46 [2] c5 64 [2] d1 7f [2] de 65 [2] c0 78 [2] c2 79 [2] d9 7f [2] c5 78 [2] d9 57 }

  condition:
    any of them
}