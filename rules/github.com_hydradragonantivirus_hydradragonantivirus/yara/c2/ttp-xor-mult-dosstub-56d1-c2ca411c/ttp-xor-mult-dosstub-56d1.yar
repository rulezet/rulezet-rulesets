rule TTP_XOR_MULT_DOSStub_56d1 {
  strings:
    $key_56d1 = { 02 b9 [2] 76 a1 [2] 31 a3 [2] 76 b2 [2] 38 be [2] 34 b4 [2] 23 bf [2] 38 f1 [2] 05 }

  condition:
    any of them
}