rule TTP_XOR_QUAD_CurrentVersionRun_15db {
  strings:
    $key_15db = { 46 b4 [2] 62 ba [2] 49 96 [2] 67 b4 [2] 73 af [2] 7c b5 [2] 62 a8 [2] 60 a9 [2] 7b af [2] 67 a8 [2] 7b 87 }

  condition:
    any of them
}