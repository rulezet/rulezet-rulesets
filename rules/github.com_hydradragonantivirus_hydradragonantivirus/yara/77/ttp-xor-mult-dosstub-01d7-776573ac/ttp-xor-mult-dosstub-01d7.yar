rule TTP_XOR_MULT_DOSStub_01d7 {
  strings:
    $key_01d7 = { 55 bf [2] 21 a7 [2] 66 a5 [2] 21 b4 [2] 6f b8 [2] 63 b2 [2] 74 b9 [2] 6f f7 [2] 52 }

  condition:
    any of them
}