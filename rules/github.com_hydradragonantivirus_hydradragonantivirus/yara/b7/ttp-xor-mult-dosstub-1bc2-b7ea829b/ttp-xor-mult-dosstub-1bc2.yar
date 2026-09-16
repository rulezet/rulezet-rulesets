rule TTP_XOR_MULT_DOSStub_1bc2 {
  strings:
    $key_1bc2 = { 4f aa [2] 3b b2 [2] 7c b0 [2] 3b a1 [2] 75 ad [2] 79 a7 [2] 6e ac [2] 75 e2 [2] 48 }

  condition:
    any of them
}