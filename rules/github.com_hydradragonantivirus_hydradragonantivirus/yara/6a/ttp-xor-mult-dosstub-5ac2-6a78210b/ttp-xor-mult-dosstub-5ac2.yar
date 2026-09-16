rule TTP_XOR_MULT_DOSStub_5ac2 {
  strings:
    $key_5ac2 = { 0e aa [2] 7a b2 [2] 3d b0 [2] 7a a1 [2] 34 ad [2] 38 a7 [2] 2f ac [2] 34 e2 [2] 09 }

  condition:
    any of them
}