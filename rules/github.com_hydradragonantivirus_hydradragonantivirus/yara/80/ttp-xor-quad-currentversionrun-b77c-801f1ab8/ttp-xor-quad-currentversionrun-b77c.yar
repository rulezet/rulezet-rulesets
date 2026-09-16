rule TTP_XOR_QUAD_CurrentVersionRun_b77c {
  strings:
    $key_b77c = { e4 13 [2] c0 1d [2] eb 31 [2] c5 13 [2] d1 08 [2] de 12 [2] c0 0f [2] c2 0e [2] d9 08 [2] c5 0f [2] d9 20 }

  condition:
    any of them
}