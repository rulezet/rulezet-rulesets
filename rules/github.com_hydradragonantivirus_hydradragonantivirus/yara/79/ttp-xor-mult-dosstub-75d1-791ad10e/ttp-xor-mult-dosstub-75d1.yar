rule TTP_XOR_MULT_DOSStub_75d1 {
  strings:
    $key_75d1 = { 21 b9 [2] 55 a1 [2] 12 a3 [2] 55 b2 [2] 1b be [2] 17 b4 [2] 00 bf [2] 1b f1 [2] 26 }

  condition:
    any of them
}