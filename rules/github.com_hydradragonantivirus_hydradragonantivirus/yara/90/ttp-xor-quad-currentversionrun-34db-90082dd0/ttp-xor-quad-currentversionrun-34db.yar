rule TTP_XOR_QUAD_CurrentVersionRun_34db {
  strings:
    $key_34db = { 67 b4 [2] 43 ba [2] 68 96 [2] 46 b4 [2] 52 af [2] 5d b5 [2] 43 a8 [2] 41 a9 [2] 5a af [2] 46 a8 [2] 5a 87 }

  condition:
    any of them
}