rule TTP_XOR_MULT_DOSStub_56d7 {
  strings:
    $key_56d7 = { 02 bf [2] 76 a7 [2] 31 a5 [2] 76 b4 [2] 38 b8 [2] 34 b2 [2] 23 b9 [2] 38 f7 [2] 05 }

  condition:
    any of them
}