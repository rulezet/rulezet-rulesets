rule TTP_XOR_MULT_DOSStub_1dd1 {
  strings:
    $key_1dd1 = { 49 b9 [2] 3d a1 [2] 7a a3 [2] 3d b2 [2] 73 be [2] 7f b4 [2] 68 bf [2] 73 f1 [2] 4e }

  condition:
    any of them
}