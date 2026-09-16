rule TTP_XOR_QUAD_CurrentVersionRun_38db {
  strings:
    $key_38db = { 6b b4 [2] 4f ba [2] 64 96 [2] 4a b4 [2] 5e af [2] 51 b5 [2] 4f a8 [2] 4d a9 [2] 56 af [2] 4a a8 [2] 56 87 }

  condition:
    any of them
}