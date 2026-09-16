rule TTP_XOR_QUAD_CurrentVersionRun_b3c0 {
  strings:
    $key_b3c0 = { e0 af [2] c4 a1 [2] ef 8d [2] c1 af [2] d5 b4 [2] da ae [2] c4 b3 [2] c6 b2 [2] dd b4 [2] c1 b3 [2] dd 9c }

  condition:
    any of them
}