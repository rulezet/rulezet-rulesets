rule TTP_XOR_QUAD_CurrentVersionRun_b79d {
  strings:
    $key_b79d = { e4 f2 [2] c0 fc [2] eb d0 [2] c5 f2 [2] d1 e9 [2] de f3 [2] c0 ee [2] c2 ef [2] d9 e9 [2] c5 ee [2] d9 c1 }

  condition:
    any of them
}