rule TTP_XOR_QUAD_CurrentVersionRun_b700 {
  strings:
    $key_b700 = { e4 6f [2] c0 61 [2] eb 4d [2] c5 6f [2] d1 74 [2] de 6e [2] c0 73 [2] c2 72 [2] d9 74 [2] c5 73 [2] d9 5c }

  condition:
    any of them
}