rule TTP_XOR_QUAD_CurrentVersionRun_b7c0 {
  strings:
    $key_b7c0 = { e4 af [2] c0 a1 [2] eb 8d [2] c5 af [2] d1 b4 [2] de ae [2] c0 b3 [2] c2 b2 [2] d9 b4 [2] c5 b3 [2] d9 9c }

  condition:
    any of them
}