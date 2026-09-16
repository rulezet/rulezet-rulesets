rule TTP_XOR_QUAD_CurrentVersionRun_58db {
  strings:
    $key_58db = { 0b b4 [2] 2f ba [2] 04 96 [2] 2a b4 [2] 3e af [2] 31 b5 [2] 2f a8 [2] 2d a9 [2] 36 af [2] 2a a8 [2] 36 87 }

  condition:
    any of them
}