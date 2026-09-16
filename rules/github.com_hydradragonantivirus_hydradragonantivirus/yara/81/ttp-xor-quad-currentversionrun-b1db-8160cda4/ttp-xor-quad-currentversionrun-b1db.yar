rule TTP_XOR_QUAD_CurrentVersionRun_b1db {
  strings:
    $key_b1db = { e2 b4 [2] c6 ba [2] ed 96 [2] c3 b4 [2] d7 af [2] d8 b5 [2] c6 a8 [2] c4 a9 [2] df af [2] c3 a8 [2] df 87 }

  condition:
    any of them
}