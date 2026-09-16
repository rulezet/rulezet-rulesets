rule TTP_XOR_MULT_DOSStub_70d7 {
  strings:
    $key_70d7 = { 24 bf [2] 50 a7 [2] 17 a5 [2] 50 b4 [2] 1e b8 [2] 12 b2 [2] 05 b9 [2] 1e f7 [2] 23 }

  condition:
    any of them
}