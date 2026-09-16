rule TTP_XOR_MULT_DOSStub_4ac9 {
  strings:
    $key_4ac9 = { 1e a1 [2] 6a b9 [2] 2d bb [2] 6a aa [2] 24 a6 [2] 28 ac [2] 3f a7 [2] 24 e9 [2] 19 }

  condition:
    any of them
}