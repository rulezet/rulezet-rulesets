rule TTP_XOR_QUAD_CurrentVersionRun_b7db {
  strings:
    $key_b7db = { e4 b4 [2] c0 ba [2] eb 96 [2] c5 b4 [2] d1 af [2] de b5 [2] c0 a8 [2] c2 a9 [2] d9 af [2] c5 a8 [2] d9 87 }

  condition:
    any of them
}