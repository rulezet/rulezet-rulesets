rule TTP_XOR_QUAD_CurrentVersionRun_64db {
  strings:
    $key_64db = { 37 b4 [2] 13 ba [2] 38 96 [2] 16 b4 [2] 02 af [2] 0d b5 [2] 13 a8 [2] 11 a9 [2] 0a af [2] 16 a8 [2] 0a 87 }

  condition:
    any of them
}