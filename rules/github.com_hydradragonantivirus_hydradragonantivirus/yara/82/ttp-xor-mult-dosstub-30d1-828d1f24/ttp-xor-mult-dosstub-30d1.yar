rule TTP_XOR_MULT_DOSStub_30d1 {
  strings:
    $key_30d1 = { 64 b9 [2] 10 a1 [2] 57 a3 [2] 10 b2 [2] 5e be [2] 52 b4 [2] 45 bf [2] 5e f1 [2] 63 }

  condition:
    any of them
}