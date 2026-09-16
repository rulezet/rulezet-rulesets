rule TTP_XOR_MULT_DOSStub_3ac2 {
  strings:
    $key_3ac2 = { 6e aa [2] 1a b2 [2] 5d b0 [2] 1a a1 [2] 54 ad [2] 58 a7 [2] 4f ac [2] 54 e2 [2] 69 }

  condition:
    any of them
}