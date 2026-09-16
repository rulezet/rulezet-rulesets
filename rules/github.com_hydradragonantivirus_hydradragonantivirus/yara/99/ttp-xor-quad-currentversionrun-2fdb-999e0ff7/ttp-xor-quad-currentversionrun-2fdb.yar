rule TTP_XOR_QUAD_CurrentVersionRun_2fdb {
  strings:
    $key_2fdb = { 7c b4 [2] 58 ba [2] 73 96 [2] 5d b4 [2] 49 af [2] 46 b5 [2] 58 a8 [2] 5a a9 [2] 41 af [2] 5d a8 [2] 41 87 }

  condition:
    any of them
}