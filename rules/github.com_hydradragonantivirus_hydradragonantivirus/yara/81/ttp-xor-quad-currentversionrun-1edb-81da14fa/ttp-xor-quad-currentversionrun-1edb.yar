rule TTP_XOR_QUAD_CurrentVersionRun_1edb {
  strings:
    $key_1edb = { 4d b4 [2] 69 ba [2] 42 96 [2] 6c b4 [2] 78 af [2] 77 b5 [2] 69 a8 [2] 6b a9 [2] 70 af [2] 6c a8 [2] 70 87 }

  condition:
    any of them
}