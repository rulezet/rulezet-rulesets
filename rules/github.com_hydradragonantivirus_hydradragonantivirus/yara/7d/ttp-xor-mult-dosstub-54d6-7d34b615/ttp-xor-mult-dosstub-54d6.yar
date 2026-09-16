rule TTP_XOR_MULT_DOSStub_54d6 {
  strings:
    $key_54d6 = { 00 be [2] 74 a6 [2] 33 a4 [2] 74 b5 [2] 3a b9 [2] 36 b3 [2] 21 b8 [2] 3a f6 [2] 07 }

  condition:
    any of them
}