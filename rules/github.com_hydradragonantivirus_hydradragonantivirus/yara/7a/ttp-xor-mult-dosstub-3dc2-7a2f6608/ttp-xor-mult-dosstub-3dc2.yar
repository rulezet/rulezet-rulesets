rule TTP_XOR_MULT_DOSStub_3dc2 {
  strings:
    $key_3dc2 = { 69 aa [2] 1d b2 [2] 5a b0 [2] 1d a1 [2] 53 ad [2] 5f a7 [2] 48 ac [2] 53 e2 [2] 6e }

  condition:
    any of them
}