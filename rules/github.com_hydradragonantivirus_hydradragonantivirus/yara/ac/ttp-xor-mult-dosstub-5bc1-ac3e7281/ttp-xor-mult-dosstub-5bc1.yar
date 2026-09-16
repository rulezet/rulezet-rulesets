rule TTP_XOR_MULT_DOSStub_5bc1 {
  strings:
    $key_5bc1 = { 0f a9 [2] 7b b1 [2] 3c b3 [2] 7b a2 [2] 35 ae [2] 39 a4 [2] 2e af [2] 35 e1 [2] 08 }

  condition:
    any of them
}