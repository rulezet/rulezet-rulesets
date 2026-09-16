rule TTP_XOR_QUAD_CurrentVersionRun_08db {
  strings:
    $key_08db = { 5b b4 [2] 7f ba [2] 54 96 [2] 7a b4 [2] 6e af [2] 61 b5 [2] 7f a8 [2] 7d a9 [2] 66 af [2] 7a a8 [2] 66 87 }

  condition:
    any of them
}