rule TTP_XOR_MULT_DOSStub_1cc6 {
  strings:
    $key_1cc6 = { 48 ae [2] 3c b6 [2] 7b b4 [2] 3c a5 [2] 72 a9 [2] 7e a3 [2] 69 a8 [2] 72 e6 [2] 4f }

  condition:
    any of them
}