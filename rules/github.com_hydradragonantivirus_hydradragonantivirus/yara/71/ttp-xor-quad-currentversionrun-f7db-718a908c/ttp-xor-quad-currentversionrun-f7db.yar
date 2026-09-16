rule TTP_XOR_QUAD_CurrentVersionRun_f7db {
  strings:
    $key_f7db = { a4 b4 [2] 80 ba [2] ab 96 [2] 85 b4 [2] 91 af [2] 9e b5 [2] 80 a8 [2] 82 a9 [2] 99 af [2] 85 a8 [2] 99 87 }

  condition:
    any of them
}