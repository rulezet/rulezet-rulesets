rule TTP_XOR_QUAD_CurrentVersionRun_b756 {
  strings:
    $key_b756 = { e4 39 [2] c0 37 [2] eb 1b [2] c5 39 [2] d1 22 [2] de 38 [2] c0 25 [2] c2 24 [2] d9 22 [2] c5 25 [2] d9 0a }

  condition:
    any of them
}