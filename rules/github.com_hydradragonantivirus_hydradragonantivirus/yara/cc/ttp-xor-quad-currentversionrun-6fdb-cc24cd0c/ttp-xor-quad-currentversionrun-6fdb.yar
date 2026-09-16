rule TTP_XOR_QUAD_CurrentVersionRun_6fdb {
  strings:
    $key_6fdb = { 3c b4 [2] 18 ba [2] 33 96 [2] 1d b4 [2] 09 af [2] 06 b5 [2] 18 a8 [2] 1a a9 [2] 01 af [2] 1d a8 [2] 01 87 }

  condition:
    any of them
}