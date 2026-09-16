rule TTP_XOR_MULT_DOSStub_70d1 {
  strings:
    $key_70d1 = { 24 b9 [2] 50 a1 [2] 17 a3 [2] 50 b2 [2] 1e be [2] 12 b4 [2] 05 bf [2] 1e f1 [2] 23 }

  condition:
    any of them
}