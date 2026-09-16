rule TTP_XOR_MULT_DOSStub_3bc1 {
  strings:
    $key_3bc1 = { 6f a9 [2] 1b b1 [2] 5c b3 [2] 1b a2 [2] 55 ae [2] 59 a4 [2] 4e af [2] 55 e1 [2] 68 }

  condition:
    any of them
}