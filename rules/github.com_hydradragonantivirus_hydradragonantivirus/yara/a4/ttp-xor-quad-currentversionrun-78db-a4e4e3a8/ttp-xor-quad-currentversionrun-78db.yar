rule TTP_XOR_QUAD_CurrentVersionRun_78db {
  strings:
    $key_78db = { 2b b4 [2] 0f ba [2] 24 96 [2] 0a b4 [2] 1e af [2] 11 b5 [2] 0f a8 [2] 0d a9 [2] 16 af [2] 0a a8 [2] 16 87 }

  condition:
    any of them
}