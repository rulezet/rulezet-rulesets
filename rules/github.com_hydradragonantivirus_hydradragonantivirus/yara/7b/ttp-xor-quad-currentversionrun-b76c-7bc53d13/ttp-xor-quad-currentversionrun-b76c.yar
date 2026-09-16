rule TTP_XOR_QUAD_CurrentVersionRun_b76c {
  strings:
    $key_b76c = { e4 03 [2] c0 0d [2] eb 21 [2] c5 03 [2] d1 18 [2] de 02 [2] c0 1f [2] c2 1e [2] d9 18 [2] c5 1f [2] d9 30 }

  condition:
    any of them
}