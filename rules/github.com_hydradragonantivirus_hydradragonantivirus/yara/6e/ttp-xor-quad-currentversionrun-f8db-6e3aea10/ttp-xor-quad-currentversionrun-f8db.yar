rule TTP_XOR_QUAD_CurrentVersionRun_f8db {
  strings:
    $key_f8db = { ab b4 [2] 8f ba [2] a4 96 [2] 8a b4 [2] 9e af [2] 91 b5 [2] 8f a8 [2] 8d a9 [2] 96 af [2] 8a a8 [2] 96 87 }

  condition:
    any of them
}