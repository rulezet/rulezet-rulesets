rule TTP_XOR_MULT_DOSStub_7ac4 {
  strings:
    $key_7ac4 = { 2e ac [2] 5a b4 [2] 1d b6 [2] 5a a7 [2] 14 ab [2] 18 a1 [2] 0f aa [2] 14 e4 [2] 29 }

  condition:
    any of them
}