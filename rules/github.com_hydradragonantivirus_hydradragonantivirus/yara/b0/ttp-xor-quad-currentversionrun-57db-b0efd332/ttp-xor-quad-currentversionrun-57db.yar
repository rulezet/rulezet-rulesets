rule TTP_XOR_QUAD_CurrentVersionRun_57db {
  strings:
    $key_57db = { 04 b4 [2] 20 ba [2] 0b 96 [2] 25 b4 [2] 31 af [2] 3e b5 [2] 20 a8 [2] 22 a9 [2] 39 af [2] 25 a8 [2] 39 87 }

  condition:
    any of them
}