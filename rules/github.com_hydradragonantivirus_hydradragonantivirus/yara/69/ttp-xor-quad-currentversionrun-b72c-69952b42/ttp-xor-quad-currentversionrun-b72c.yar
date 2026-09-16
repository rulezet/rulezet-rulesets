rule TTP_XOR_QUAD_CurrentVersionRun_b72c {
  strings:
    $key_b72c = { e4 43 [2] c0 4d [2] eb 61 [2] c5 43 [2] d1 58 [2] de 42 [2] c0 5f [2] c2 5e [2] d9 58 [2] c5 5f [2] d9 70 }

  condition:
    any of them
}