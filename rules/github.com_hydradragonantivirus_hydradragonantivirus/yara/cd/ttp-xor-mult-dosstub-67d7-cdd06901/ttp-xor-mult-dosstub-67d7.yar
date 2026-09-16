rule TTP_XOR_MULT_DOSStub_67d7 {
  strings:
    $key_67d7 = { 33 bf [2] 47 a7 [2] 00 a5 [2] 47 b4 [2] 09 b8 [2] 05 b2 [2] 12 b9 [2] 09 f7 [2] 34 }

  condition:
    any of them
}