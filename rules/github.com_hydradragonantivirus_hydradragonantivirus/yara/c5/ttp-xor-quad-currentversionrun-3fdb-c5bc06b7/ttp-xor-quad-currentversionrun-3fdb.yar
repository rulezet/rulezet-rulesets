rule TTP_XOR_QUAD_CurrentVersionRun_3fdb {
  strings:
    $key_3fdb = { 6c b4 [2] 48 ba [2] 63 96 [2] 4d b4 [2] 59 af [2] 56 b5 [2] 48 a8 [2] 4a a9 [2] 51 af [2] 4d a8 [2] 51 87 }

  condition:
    any of them
}