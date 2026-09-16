rule TTP_XOR_MULT_DOSStub_2dd0 {
  strings:
    $key_2dd0 = { 79 b8 [2] 0d a0 [2] 4a a2 [2] 0d b3 [2] 43 bf [2] 4f b5 [2] 58 be [2] 43 f0 [2] 7e }

  condition:
    any of them
}