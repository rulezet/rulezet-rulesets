rule TTP_XOR_MULT_DOSStub_7ac9 {
  strings:
    $key_7ac9 = { 2e a1 [2] 5a b9 [2] 1d bb [2] 5a aa [2] 14 a6 [2] 18 ac [2] 0f a7 [2] 14 e9 [2] 29 }

  condition:
    any of them
}