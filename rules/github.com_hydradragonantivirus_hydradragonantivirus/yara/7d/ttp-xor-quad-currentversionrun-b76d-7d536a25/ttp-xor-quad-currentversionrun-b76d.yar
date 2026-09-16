rule TTP_XOR_QUAD_CurrentVersionRun_b76d {
  strings:
    $key_b76d = { e4 02 [2] c0 0c [2] eb 20 [2] c5 02 [2] d1 19 [2] de 03 [2] c0 1e [2] c2 1f [2] d9 19 [2] c5 1e [2] d9 31 }

  condition:
    any of them
}