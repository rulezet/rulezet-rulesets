rule TTP_XOR_MULT_DOSStub_4bc2 {
  strings:
    $key_4bc2 = { 1f aa [2] 6b b2 [2] 2c b0 [2] 6b a1 [2] 25 ad [2] 29 a7 [2] 3e ac [2] 25 e2 [2] 18 }

  condition:
    any of them
}