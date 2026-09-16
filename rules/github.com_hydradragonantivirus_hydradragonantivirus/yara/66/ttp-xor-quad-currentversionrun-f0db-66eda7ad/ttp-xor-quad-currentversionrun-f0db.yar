rule TTP_XOR_QUAD_CurrentVersionRun_f0db {
  strings:
    $key_f0db = { a3 b4 [2] 87 ba [2] ac 96 [2] 82 b4 [2] 96 af [2] 99 b5 [2] 87 a8 [2] 85 a9 [2] 9e af [2] 82 a8 [2] 9e 87 }

  condition:
    any of them
}