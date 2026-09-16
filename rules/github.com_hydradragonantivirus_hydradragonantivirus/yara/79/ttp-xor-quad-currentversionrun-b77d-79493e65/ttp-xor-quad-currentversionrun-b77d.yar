rule TTP_XOR_QUAD_CurrentVersionRun_b77d {
  strings:
    $key_b77d = { e4 12 [2] c0 1c [2] eb 30 [2] c5 12 [2] d1 09 [2] de 13 [2] c0 0e [2] c2 0f [2] d9 09 [2] c5 0e [2] d9 21 }

  condition:
    any of them
}