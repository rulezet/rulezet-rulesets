rule TTP_XOR_MULT_DOSStub_4dc4 {
  strings:
    $key_4dc4 = { 19 ac [2] 6d b4 [2] 2a b6 [2] 6d a7 [2] 23 ab [2] 2f a1 [2] 38 aa [2] 23 e4 [2] 1e }

  condition:
    any of them
}