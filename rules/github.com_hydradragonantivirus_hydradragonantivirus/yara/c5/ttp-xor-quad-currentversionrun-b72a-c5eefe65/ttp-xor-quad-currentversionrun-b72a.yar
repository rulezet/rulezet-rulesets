rule TTP_XOR_QUAD_CurrentVersionRun_b72a {
  strings:
    $key_b72a = { e4 45 [2] c0 4b [2] eb 67 [2] c5 45 [2] d1 5e [2] de 44 [2] c0 59 [2] c2 58 [2] d9 5e [2] c5 59 [2] d9 76 }

  condition:
    any of them
}