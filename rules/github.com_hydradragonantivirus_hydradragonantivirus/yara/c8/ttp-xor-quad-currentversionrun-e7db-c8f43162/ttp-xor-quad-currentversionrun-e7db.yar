rule TTP_XOR_QUAD_CurrentVersionRun_e7db {
  strings:
    $key_e7db = { b4 b4 [2] 90 ba [2] bb 96 [2] 95 b4 [2] 81 af [2] 8e b5 [2] 90 a8 [2] 92 a9 [2] 89 af [2] 95 a8 [2] 89 87 }

  condition:
    any of them
}