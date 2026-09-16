rule TTP_XOR_MULT_DOSStub_3bc2 {
  strings:
    $key_3bc2 = { 6f aa [2] 1b b2 [2] 5c b0 [2] 1b a1 [2] 55 ad [2] 59 a7 [2] 4e ac [2] 55 e2 [2] 68 }

  condition:
    any of them
}