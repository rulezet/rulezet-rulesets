rule TTP_XOR_QUAD_CurrentVersionRun_b726 {
  strings:
    $key_b726 = { e4 49 [2] c0 47 [2] eb 6b [2] c5 49 [2] d1 52 [2] de 48 [2] c0 55 [2] c2 54 [2] d9 52 [2] c5 55 [2] d9 7a }

  condition:
    any of them
}