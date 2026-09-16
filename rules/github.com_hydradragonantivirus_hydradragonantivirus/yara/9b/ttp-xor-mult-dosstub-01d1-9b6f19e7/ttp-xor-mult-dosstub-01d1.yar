rule TTP_XOR_MULT_DOSStub_01d1 {
  strings:
    $key_01d1 = { 55 b9 [2] 21 a1 [2] 66 a3 [2] 21 b2 [2] 6f be [2] 63 b4 [2] 74 bf [2] 6f f1 [2] 52 }

  condition:
    any of them
}