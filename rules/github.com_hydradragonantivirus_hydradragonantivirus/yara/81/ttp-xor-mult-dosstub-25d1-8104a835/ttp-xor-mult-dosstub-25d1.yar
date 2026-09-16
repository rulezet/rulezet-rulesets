rule TTP_XOR_MULT_DOSStub_25d1 {
  strings:
    $key_25d1 = { 71 b9 [2] 05 a1 [2] 42 a3 [2] 05 b2 [2] 4b be [2] 47 b4 [2] 50 bf [2] 4b f1 [2] 76 }

  condition:
    any of them
}