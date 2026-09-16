rule TTP_XOR_QUAD_CurrentVersionRun_f2db {
  strings:
    $key_f2db = { a1 b4 [2] 85 ba [2] ae 96 [2] 80 b4 [2] 94 af [2] 9b b5 [2] 85 a8 [2] 87 a9 [2] 9c af [2] 80 a8 [2] 9c 87 }

  condition:
    any of them
}