rule TTP_XOR_MULT_DOSStub_1dd7 {
  strings:
    $key_1dd7 = { 49 bf [2] 3d a7 [2] 7a a5 [2] 3d b4 [2] 73 b8 [2] 7f b2 [2] 68 b9 [2] 73 f7 [2] 4e }

  condition:
    any of them
}