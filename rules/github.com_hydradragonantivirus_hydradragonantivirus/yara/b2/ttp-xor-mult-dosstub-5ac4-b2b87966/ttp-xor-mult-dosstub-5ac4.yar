rule TTP_XOR_MULT_DOSStub_5ac4 {
  strings:
    $key_5ac4 = { 0e ac [2] 7a b4 [2] 3d b6 [2] 7a a7 [2] 34 ab [2] 38 a1 [2] 2f aa [2] 34 e4 [2] 09 }

  condition:
    any of them
}