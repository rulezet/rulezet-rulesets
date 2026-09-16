rule TTP_XOR_QUAD_CurrentVersionRun_b4db {
  strings:
    $key_b4db = { e7 b4 [2] c3 ba [2] e8 96 [2] c6 b4 [2] d2 af [2] dd b5 [2] c3 a8 [2] c1 a9 [2] da af [2] c6 a8 [2] da 87 }

  condition:
    any of them
}