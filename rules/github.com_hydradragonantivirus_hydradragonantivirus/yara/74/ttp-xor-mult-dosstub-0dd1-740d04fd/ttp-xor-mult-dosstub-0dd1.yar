rule TTP_XOR_MULT_DOSStub_0dd1 {
  strings:
    $key_0dd1 = { 59 b9 [2] 2d a1 [2] 6a a3 [2] 2d b2 [2] 63 be [2] 6f b4 [2] 78 bf [2] 63 f1 [2] 5e }

  condition:
    any of them
}