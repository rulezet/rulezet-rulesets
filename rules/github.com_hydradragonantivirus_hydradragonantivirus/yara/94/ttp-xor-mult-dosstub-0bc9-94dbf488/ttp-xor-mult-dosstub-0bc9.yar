rule TTP_XOR_MULT_DOSStub_0bc9 {
  strings:
    $key_0bc9 = { 5f a1 [2] 2b b9 [2] 6c bb [2] 2b aa [2] 65 a6 [2] 69 ac [2] 7e a7 [2] 65 e9 [2] 58 }

  condition:
    any of them
}