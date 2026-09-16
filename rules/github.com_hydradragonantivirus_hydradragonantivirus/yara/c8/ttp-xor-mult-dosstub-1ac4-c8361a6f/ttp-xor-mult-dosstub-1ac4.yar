rule TTP_XOR_MULT_DOSStub_1ac4 {
  strings:
    $key_1ac4 = { 4e ac [2] 3a b4 [2] 7d b6 [2] 3a a7 [2] 74 ab [2] 78 a1 [2] 6f aa [2] 74 e4 [2] 49 }

  condition:
    any of them
}