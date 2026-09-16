rule TTP_XOR_QUAD_CurrentVersionRun_b79b {
  strings:
    $key_b79b = { e4 f4 [2] c0 fa [2] eb d6 [2] c5 f4 [2] d1 ef [2] de f5 [2] c0 e8 [2] c2 e9 [2] d9 ef [2] c5 e8 [2] d9 c7 }

  condition:
    any of them
}