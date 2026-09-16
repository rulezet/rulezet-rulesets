rule TTP_XOR_QUAD_CurrentVersionRun_0fdb {
  strings:
    $key_0fdb = { 5c b4 [2] 78 ba [2] 53 96 [2] 7d b4 [2] 69 af [2] 66 b5 [2] 78 a8 [2] 7a a9 [2] 61 af [2] 7d a8 [2] 61 87 }

  condition:
    any of them
}