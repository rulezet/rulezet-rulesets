rule TTP_XOR_QUAD_CurrentVersionRun_7edb {
  strings:
    $key_7edb = { 2d b4 [2] 09 ba [2] 22 96 [2] 0c b4 [2] 18 af [2] 17 b5 [2] 09 a8 [2] 0b a9 [2] 10 af [2] 0c a8 [2] 10 87 }

  condition:
    any of them
}