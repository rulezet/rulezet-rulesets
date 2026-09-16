rule TTP_XOR_MULT_DOSStub_59c2 {
  strings:
    $key_59c2 = { 0d aa [2] 79 b2 [2] 3e b0 [2] 79 a1 [2] 37 ad [2] 3b a7 [2] 2c ac [2] 37 e2 [2] 0a }

  condition:
    any of them
}