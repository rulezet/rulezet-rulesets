rule TTP_XOR_QUAD_CurrentVersionRun_1fdb {
  strings:
    $key_1fdb = { 4c b4 [2] 68 ba [2] 43 96 [2] 6d b4 [2] 79 af [2] 76 b5 [2] 68 a8 [2] 6a a9 [2] 71 af [2] 6d a8 [2] 71 87 }

  condition:
    any of them
}