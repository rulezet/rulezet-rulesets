rule TTP_XOR_MULT_DOSStub_f2d7 {
  strings:
    $key_f2d7 = { a6 bf [2] d2 a7 [2] 95 a5 [2] d2 b4 [2] 9c b8 [2] 90 b2 [2] 87 b9 [2] 9c f7 [2] a1 }

  condition:
    any of them
}