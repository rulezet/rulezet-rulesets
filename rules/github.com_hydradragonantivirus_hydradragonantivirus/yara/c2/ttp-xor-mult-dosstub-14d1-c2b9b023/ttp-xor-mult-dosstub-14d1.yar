rule TTP_XOR_MULT_DOSStub_14d1 {
  strings:
    $key_14d1 = { 40 b9 [2] 34 a1 [2] 73 a3 [2] 34 b2 [2] 7a be [2] 76 b4 [2] 61 bf [2] 7a f1 [2] 47 }

  condition:
    any of them
}