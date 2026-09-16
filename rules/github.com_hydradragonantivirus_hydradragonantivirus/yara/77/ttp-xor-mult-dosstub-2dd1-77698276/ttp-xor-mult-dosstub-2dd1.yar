rule TTP_XOR_MULT_DOSStub_2dd1 {
  strings:
    $key_2dd1 = { 79 b9 [2] 0d a1 [2] 4a a3 [2] 0d b2 [2] 43 be [2] 4f b4 [2] 58 bf [2] 43 f1 [2] 7e }

  condition:
    any of them
}