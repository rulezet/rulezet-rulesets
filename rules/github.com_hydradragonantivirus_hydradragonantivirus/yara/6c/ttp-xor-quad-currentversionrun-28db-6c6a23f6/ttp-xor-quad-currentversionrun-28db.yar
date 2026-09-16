rule TTP_XOR_QUAD_CurrentVersionRun_28db {
  strings:
    $key_28db = { 7b b4 [2] 5f ba [2] 74 96 [2] 5a b4 [2] 4e af [2] 41 b5 [2] 5f a8 [2] 5d a9 [2] 46 af [2] 5a a8 [2] 46 87 }

  condition:
    any of them
}