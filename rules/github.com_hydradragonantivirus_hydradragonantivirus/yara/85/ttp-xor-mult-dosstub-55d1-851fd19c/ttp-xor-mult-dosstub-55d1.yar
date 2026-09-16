rule TTP_XOR_MULT_DOSStub_55d1 {
  strings:
    $key_55d1 = { 01 b9 [2] 75 a1 [2] 32 a3 [2] 75 b2 [2] 3b be [2] 37 b4 [2] 20 bf [2] 3b f1 [2] 06 }

  condition:
    any of them
}