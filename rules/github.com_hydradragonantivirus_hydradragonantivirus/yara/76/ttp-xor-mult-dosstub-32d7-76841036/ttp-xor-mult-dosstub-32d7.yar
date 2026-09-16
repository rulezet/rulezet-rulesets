rule TTP_XOR_MULT_DOSStub_32d7 {
  strings:
    $key_32d7 = { 66 bf [2] 12 a7 [2] 55 a5 [2] 12 b4 [2] 5c b8 [2] 50 b2 [2] 47 b9 [2] 5c f7 [2] 61 }

  condition:
    any of them
}