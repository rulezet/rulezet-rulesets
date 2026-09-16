rule TTP_XOR_QUAD_CurrentVersionRun_48db {
  strings:
    $key_48db = { 1b b4 [2] 3f ba [2] 14 96 [2] 3a b4 [2] 2e af [2] 21 b5 [2] 3f a8 [2] 3d a9 [2] 26 af [2] 3a a8 [2] 26 87 }

  condition:
    any of them
}