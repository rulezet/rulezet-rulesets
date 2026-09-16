rule TTP_XOR_QUAD_CurrentVersionRun_3edb {
  strings:
    $key_3edb = { 6d b4 [2] 49 ba [2] 62 96 [2] 4c b4 [2] 58 af [2] 57 b5 [2] 49 a8 [2] 4b a9 [2] 50 af [2] 4c a8 [2] 50 87 }

  condition:
    any of them
}