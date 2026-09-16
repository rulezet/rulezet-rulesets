rule TTP_XOR_MULT_DOSStub_49c2 {
  strings:
    $key_49c2 = { 1d aa [2] 69 b2 [2] 2e b0 [2] 69 a1 [2] 27 ad [2] 2b a7 [2] 3c ac [2] 27 e2 [2] 1a }

  condition:
    any of them
}