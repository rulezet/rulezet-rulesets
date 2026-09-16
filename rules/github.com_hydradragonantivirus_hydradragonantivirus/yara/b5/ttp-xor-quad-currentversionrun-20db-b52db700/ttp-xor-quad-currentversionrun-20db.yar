rule TTP_XOR_QUAD_CurrentVersionRun_20db {
  strings:
    $key_20db = { 73 b4 [2] 57 ba [2] 7c 96 [2] 52 b4 [2] 46 af [2] 49 b5 [2] 57 a8 [2] 55 a9 [2] 4e af [2] 52 a8 [2] 4e 87 }

  condition:
    any of them
}