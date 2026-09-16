rule TTP_XOR_QUAD_CurrentVersionRun_b72d {
  strings:
    $key_b72d = { e4 42 [2] c0 4c [2] eb 60 [2] c5 42 [2] d1 59 [2] de 43 [2] c0 5e [2] c2 5f [2] d9 59 [2] c5 5e [2] d9 71 }

  condition:
    any of them
}