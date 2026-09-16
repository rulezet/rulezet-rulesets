rule TTP_XOR_MULT_DOSStub_1cc7 {
  strings:
    $key_1cc7 = { 48 af [2] 3c b7 [2] 7b b5 [2] 3c a4 [2] 72 a8 [2] 7e a2 [2] 69 a9 [2] 72 e7 [2] 4f }

  condition:
    any of them
}