rule TTP_XOR_QUAD_CurrentVersionRun_b771 {
  strings:
    $key_b771 = { e4 1e [2] c0 10 [2] eb 3c [2] c5 1e [2] d1 05 [2] de 1f [2] c0 02 [2] c2 03 [2] d9 05 [2] c5 02 [2] d9 2d }

  condition:
    any of them
}