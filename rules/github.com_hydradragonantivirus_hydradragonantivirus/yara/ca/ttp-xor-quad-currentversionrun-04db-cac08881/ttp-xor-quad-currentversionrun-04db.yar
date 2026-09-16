rule TTP_XOR_QUAD_CurrentVersionRun_04db {
  strings:
    $key_04db = { 57 b4 [2] 73 ba [2] 58 96 [2] 76 b4 [2] 62 af [2] 6d b5 [2] 73 a8 [2] 71 a9 [2] 6a af [2] 76 a8 [2] 6a 87 }

  condition:
    any of them
}