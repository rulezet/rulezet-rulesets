rule TTP_XOR_QUAD_CurrentVersionRun_b71a {
  strings:
    $key_b71a = { e4 75 [2] c0 7b [2] eb 57 [2] c5 75 [2] d1 6e [2] de 74 [2] c0 69 [2] c2 68 [2] d9 6e [2] c5 69 [2] d9 46 }

  condition:
    any of them
}