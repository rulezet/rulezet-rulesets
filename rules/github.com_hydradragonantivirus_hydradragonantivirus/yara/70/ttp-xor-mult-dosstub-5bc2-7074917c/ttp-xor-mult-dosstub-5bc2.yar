rule TTP_XOR_MULT_DOSStub_5bc2 {
  strings:
    $key_5bc2 = { 0f aa [2] 7b b2 [2] 3c b0 [2] 7b a1 [2] 35 ad [2] 39 a7 [2] 2e ac [2] 35 e2 [2] 08 }

  condition:
    any of them
}