rule TTP_XOR_MULT_DOSStub_10d1 {
  strings:
    $key_10d1 = { 44 b9 [2] 30 a1 [2] 77 a3 [2] 30 b2 [2] 7e be [2] 72 b4 [2] 65 bf [2] 7e f1 [2] 43 }

  condition:
    any of them
}