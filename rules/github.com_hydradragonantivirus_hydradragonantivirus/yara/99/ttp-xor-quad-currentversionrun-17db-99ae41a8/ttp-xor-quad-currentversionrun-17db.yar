rule TTP_XOR_QUAD_CurrentVersionRun_17db {
  strings:
    $key_17db = { 44 b4 [2] 60 ba [2] 4b 96 [2] 65 b4 [2] 71 af [2] 7e b5 [2] 60 a8 [2] 62 a9 [2] 79 af [2] 65 a8 [2] 79 87 }

  condition:
    any of them
}