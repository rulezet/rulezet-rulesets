rule TTP_XOR_MULT_DOSStub_40d7 {
  strings:
    $key_40d7 = { 14 bf [2] 60 a7 [2] 27 a5 [2] 60 b4 [2] 2e b8 [2] 22 b2 [2] 35 b9 [2] 2e f7 [2] 13 }

  condition:
    any of them
}