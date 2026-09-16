rule TTP_XOR_MULT_DOSStub_4dd0 {
  strings:
    $key_4dd0 = { 19 b8 [2] 6d a0 [2] 2a a2 [2] 6d b3 [2] 23 bf [2] 2f b5 [2] 38 be [2] 23 f0 [2] 1e }

  condition:
    any of them
}