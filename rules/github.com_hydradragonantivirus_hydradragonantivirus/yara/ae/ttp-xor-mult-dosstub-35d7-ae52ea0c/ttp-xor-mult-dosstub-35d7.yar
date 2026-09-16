rule TTP_XOR_MULT_DOSStub_35d7 {
  strings:
    $key_35d7 = { 61 bf [2] 15 a7 [2] 52 a5 [2] 15 b4 [2] 5b b8 [2] 57 b2 [2] 40 b9 [2] 5b f7 [2] 66 }

  condition:
    any of them
}