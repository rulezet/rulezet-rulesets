rule TTP_XOR_QUAD_CurrentVersionRun_b4dd {
  strings:
    $key_b4dd = { e7 b2 [2] c3 bc [2] e8 90 [2] c6 b2 [2] d2 a9 [2] dd b3 [2] c3 ae [2] c1 af [2] da a9 [2] c6 ae [2] da 81 }

  condition:
    any of them
}