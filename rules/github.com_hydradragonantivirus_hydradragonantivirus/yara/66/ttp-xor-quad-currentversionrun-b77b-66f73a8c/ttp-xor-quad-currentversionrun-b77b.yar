rule TTP_XOR_QUAD_CurrentVersionRun_b77b {
  strings:
    $key_b77b = { e4 14 [2] c0 1a [2] eb 36 [2] c5 14 [2] d1 0f [2] de 15 [2] c0 08 [2] c2 09 [2] d9 0f [2] c5 08 [2] d9 27 }

  condition:
    any of them
}