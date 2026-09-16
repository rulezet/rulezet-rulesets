rule TTP_XOR_MULT_DOSStub_3bc0 {
  strings:
    $key_3bc0 = { 6f a8 [2] 1b b0 [2] 5c b2 [2] 1b a3 [2] 55 af [2] 59 a5 [2] 4e ae [2] 55 e0 [2] 68 }

  condition:
    any of them
}