rule TTP_XOR_QUAD_CurrentVersionRun_b71d {
  strings:
    $key_b71d = { e4 72 [2] c0 7c [2] eb 50 [2] c5 72 [2] d1 69 [2] de 73 [2] c0 6e [2] c2 6f [2] d9 69 [2] c5 6e [2] d9 41 }

  condition:
    any of them
}