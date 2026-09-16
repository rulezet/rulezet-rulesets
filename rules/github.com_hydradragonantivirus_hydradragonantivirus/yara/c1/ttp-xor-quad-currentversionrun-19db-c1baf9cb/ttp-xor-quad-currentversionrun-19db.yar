rule TTP_XOR_QUAD_CurrentVersionRun_19db {
  strings:
    $key_19db = { 4a b4 [2] 6e ba [2] 45 96 [2] 6b b4 [2] 7f af [2] 70 b5 [2] 6e a8 [2] 6c a9 [2] 77 af [2] 6b a8 [2] 77 87 }

  condition:
    any of them
}