rule TTP_XOR_MULT_DOSStub_5dd7 {
  strings:
    $key_5dd7 = { 09 bf [2] 7d a7 [2] 3a a5 [2] 7d b4 [2] 33 b8 [2] 3f b2 [2] 28 b9 [2] 33 f7 [2] 0e }

  condition:
    any of them
}