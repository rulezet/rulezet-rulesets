rule TTP_XOR_QUAD_CurrentVersionRun_b796 {
  strings:
    $key_b796 = { e4 f9 [2] c0 f7 [2] eb db [2] c5 f9 [2] d1 e2 [2] de f8 [2] c0 e5 [2] c2 e4 [2] d9 e2 [2] c5 e5 [2] d9 ca }

  condition:
    any of them
}