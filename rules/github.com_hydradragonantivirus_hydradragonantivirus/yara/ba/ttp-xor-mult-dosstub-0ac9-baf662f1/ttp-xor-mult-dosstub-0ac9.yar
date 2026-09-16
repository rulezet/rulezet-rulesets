rule TTP_XOR_MULT_DOSStub_0ac9 {
  strings:
    $key_0ac9 = { 5e a1 [2] 2a b9 [2] 6d bb [2] 2a aa [2] 64 a6 [2] 68 ac [2] 7f a7 [2] 64 e9 [2] 59 }

  condition:
    any of them
}