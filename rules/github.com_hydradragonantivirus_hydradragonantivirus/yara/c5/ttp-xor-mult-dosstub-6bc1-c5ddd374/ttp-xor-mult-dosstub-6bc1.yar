rule TTP_XOR_MULT_DOSStub_6bc1 {
  strings:
    $key_6bc1 = { 3f a9 [2] 4b b1 [2] 0c b3 [2] 4b a2 [2] 05 ae [2] 09 a4 [2] 1e af [2] 05 e1 [2] 38 }

  condition:
    any of them
}