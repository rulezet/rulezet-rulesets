rule TTP_XOR_QUAD_CurrentVersionRun_f5db {
  strings:
    $key_f5db = { a6 b4 [2] 82 ba [2] a9 96 [2] 87 b4 [2] 93 af [2] 9c b5 [2] 82 a8 [2] 80 a9 [2] 9b af [2] 87 a8 [2] 9b 87 }

  condition:
    any of them
}