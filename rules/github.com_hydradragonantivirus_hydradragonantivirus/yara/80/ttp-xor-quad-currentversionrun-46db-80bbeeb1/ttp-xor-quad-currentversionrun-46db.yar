rule TTP_XOR_QUAD_CurrentVersionRun_46db {
  strings:
    $key_46db = { 15 b4 [2] 31 ba [2] 1a 96 [2] 34 b4 [2] 20 af [2] 2f b5 [2] 31 a8 [2] 33 a9 [2] 28 af [2] 34 a8 [2] 28 87 }

  condition:
    any of them
}