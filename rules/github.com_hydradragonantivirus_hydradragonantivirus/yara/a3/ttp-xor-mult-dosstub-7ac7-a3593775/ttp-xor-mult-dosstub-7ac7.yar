rule TTP_XOR_MULT_DOSStub_7ac7 {
  strings:
    $key_7ac7 = { 2e af [2] 5a b7 [2] 1d b5 [2] 5a a4 [2] 14 a8 [2] 18 a2 [2] 0f a9 [2] 14 e7 [2] 29 }

  condition:
    any of them
}