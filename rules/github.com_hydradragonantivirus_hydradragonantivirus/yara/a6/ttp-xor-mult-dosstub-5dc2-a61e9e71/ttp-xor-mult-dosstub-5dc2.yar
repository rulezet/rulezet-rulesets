rule TTP_XOR_MULT_DOSStub_5dc2 {
  strings:
    $key_5dc2 = { 09 aa [2] 7d b2 [2] 3a b0 [2] 7d a1 [2] 33 ad [2] 3f a7 [2] 28 ac [2] 33 e2 [2] 0e }

  condition:
    any of them
}