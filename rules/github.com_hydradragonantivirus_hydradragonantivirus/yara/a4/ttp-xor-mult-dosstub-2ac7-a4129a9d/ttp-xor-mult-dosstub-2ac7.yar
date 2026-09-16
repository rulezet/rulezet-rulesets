rule TTP_XOR_MULT_DOSStub_2ac7 {
  strings:
    $key_2ac7 = { 7e af [2] 0a b7 [2] 4d b5 [2] 0a a4 [2] 44 a8 [2] 48 a2 [2] 5f a9 [2] 44 e7 [2] 79 }

  condition:
    any of them
}