rule TTP_XOR_MULT_DOSStub_03d7 {
  strings:
    $key_03d7 = { 57 bf [2] 23 a7 [2] 64 a5 [2] 23 b4 [2] 6d b8 [2] 61 b2 [2] 76 b9 [2] 6d f7 [2] 50 }

  condition:
    any of them
}