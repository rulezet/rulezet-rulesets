rule TTP_XOR_MULT_DOSStub_f2d1 {
  strings:
    $key_f2d1 = { a6 b9 [2] d2 a1 [2] 95 a3 [2] d2 b2 [2] 9c be [2] 90 b4 [2] 87 bf [2] 9c f1 [2] a1 }

  condition:
    any of them
}