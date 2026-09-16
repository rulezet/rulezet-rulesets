rule TTP_XOR_QUAD_CurrentVersionRun_18db {
  strings:
    $key_18db = { 4b b4 [2] 6f ba [2] 44 96 [2] 6a b4 [2] 7e af [2] 71 b5 [2] 6f a8 [2] 6d a9 [2] 76 af [2] 6a a8 [2] 76 87 }

  condition:
    any of them
}