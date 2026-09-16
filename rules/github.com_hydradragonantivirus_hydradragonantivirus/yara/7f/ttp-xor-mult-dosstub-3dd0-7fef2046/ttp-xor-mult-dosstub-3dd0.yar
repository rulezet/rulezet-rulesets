rule TTP_XOR_MULT_DOSStub_3dd0 {
  strings:
    $key_3dd0 = { 69 b8 [2] 1d a0 [2] 5a a2 [2] 1d b3 [2] 53 bf [2] 5f b5 [2] 48 be [2] 53 f0 [2] 6e }

  condition:
    any of them
}