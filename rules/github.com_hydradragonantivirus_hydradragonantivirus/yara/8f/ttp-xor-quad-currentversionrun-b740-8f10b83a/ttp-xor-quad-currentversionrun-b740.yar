rule TTP_XOR_QUAD_CurrentVersionRun_b740 {
  strings:
    $key_b740 = { e4 2f [2] c0 21 [2] eb 0d [2] c5 2f [2] d1 34 [2] de 2e [2] c0 33 [2] c2 32 [2] d9 34 [2] c5 33 [2] d9 1c }

  condition:
    any of them
}