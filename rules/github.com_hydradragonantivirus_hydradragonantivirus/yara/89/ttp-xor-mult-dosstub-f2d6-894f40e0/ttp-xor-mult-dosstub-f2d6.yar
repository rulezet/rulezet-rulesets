rule TTP_XOR_MULT_DOSStub_f2d6 {
  strings:
    $key_f2d6 = { a6 be [2] d2 a6 [2] 95 a4 [2] d2 b5 [2] 9c b9 [2] 90 b3 [2] 87 b8 [2] 9c f6 [2] a1 }

  condition:
    any of them
}