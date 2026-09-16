rule TTP_XOR_MULT_DOSStub_02d7 {
  strings:
    $key_02d7 = { 56 bf [2] 22 a7 [2] 65 a5 [2] 22 b4 [2] 6c b8 [2] 60 b2 [2] 77 b9 [2] 6c f7 [2] 51 }

  condition:
    any of them
}