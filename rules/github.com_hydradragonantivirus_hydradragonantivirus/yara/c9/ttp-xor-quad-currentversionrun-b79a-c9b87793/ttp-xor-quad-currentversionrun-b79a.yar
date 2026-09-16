rule TTP_XOR_QUAD_CurrentVersionRun_b79a {
  strings:
    $key_b79a = { e4 f5 [2] c0 fb [2] eb d7 [2] c5 f5 [2] d1 ee [2] de f4 [2] c0 e9 [2] c2 e8 [2] d9 ee [2] c5 e9 [2] d9 c6 }

  condition:
    any of them
}