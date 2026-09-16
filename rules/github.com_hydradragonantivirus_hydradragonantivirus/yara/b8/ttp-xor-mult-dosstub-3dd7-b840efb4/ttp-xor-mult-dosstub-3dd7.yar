rule TTP_XOR_MULT_DOSStub_3dd7 {
  strings:
    $key_3dd7 = { 69 bf [2] 1d a7 [2] 5a a5 [2] 1d b4 [2] 53 b8 [2] 5f b2 [2] 48 b9 [2] 53 f7 [2] 6e }

  condition:
    any of them
}