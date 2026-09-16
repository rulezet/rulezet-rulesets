rule TTP_XOR_QUAD_CurrentVersionRun_09db {
  strings:
    $key_09db = { 5a b4 [2] 7e ba [2] 55 96 [2] 7b b4 [2] 6f af [2] 60 b5 [2] 7e a8 [2] 7c a9 [2] 67 af [2] 7b a8 [2] 67 87 }

  condition:
    any of them
}