rule TTP_XOR_MULT_DOSStub_5dc4 {
  strings:
    $key_5dc4 = { 09 ac [2] 7d b4 [2] 3a b6 [2] 7d a7 [2] 33 ab [2] 3f a1 [2] 28 aa [2] 33 e4 [2] 0e }

  condition:
    any of them
}