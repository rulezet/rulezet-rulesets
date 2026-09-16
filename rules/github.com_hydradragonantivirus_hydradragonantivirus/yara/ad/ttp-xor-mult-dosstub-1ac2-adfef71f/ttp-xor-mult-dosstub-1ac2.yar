rule TTP_XOR_MULT_DOSStub_1ac2 {
  strings:
    $key_1ac2 = { 4e aa [2] 3a b2 [2] 7d b0 [2] 3a a1 [2] 74 ad [2] 78 a7 [2] 6f ac [2] 74 e2 [2] 49 }

  condition:
    any of them
}