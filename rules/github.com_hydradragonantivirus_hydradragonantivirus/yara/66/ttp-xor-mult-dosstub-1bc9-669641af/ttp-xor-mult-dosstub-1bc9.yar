rule TTP_XOR_MULT_DOSStub_1bc9 {
  strings:
    $key_1bc9 = { 4f a1 [2] 3b b9 [2] 7c bb [2] 3b aa [2] 75 a6 [2] 79 ac [2] 6e a7 [2] 75 e9 [2] 48 }

  condition:
    any of them
}