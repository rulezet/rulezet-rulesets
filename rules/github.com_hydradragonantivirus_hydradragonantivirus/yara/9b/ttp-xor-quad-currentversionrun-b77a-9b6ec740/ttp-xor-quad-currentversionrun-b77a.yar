rule TTP_XOR_QUAD_CurrentVersionRun_b77a {
  strings:
    $key_b77a = { e4 15 [2] c0 1b [2] eb 37 [2] c5 15 [2] d1 0e [2] de 14 [2] c0 09 [2] c2 08 [2] d9 0e [2] c5 09 [2] d9 26 }

  condition:
    any of them
}