rule TTP_XOR_MULT_DOSStub_6dd1 {
  strings:
    $key_6dd1 = { 39 b9 [2] 4d a1 [2] 0a a3 [2] 4d b2 [2] 03 be [2] 0f b4 [2] 18 bf [2] 03 f1 [2] 3e }

  condition:
    any of them
}