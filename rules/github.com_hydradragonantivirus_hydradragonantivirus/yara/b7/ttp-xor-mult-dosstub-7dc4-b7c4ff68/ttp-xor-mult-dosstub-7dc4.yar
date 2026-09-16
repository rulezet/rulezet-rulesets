rule TTP_XOR_MULT_DOSStub_7dc4 {
  strings:
    $key_7dc4 = { 29 ac [2] 5d b4 [2] 1a b6 [2] 5d a7 [2] 13 ab [2] 1f a1 [2] 08 aa [2] 13 e4 [2] 2e }

  condition:
    any of them
}