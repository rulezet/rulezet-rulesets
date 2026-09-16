rule TTP_XOR_MULT_DOSStub_59c7 {
  strings:
    $key_59c7 = { 0d af [2] 79 b7 [2] 3e b5 [2] 79 a4 [2] 37 a8 [2] 3b a2 [2] 2c a9 [2] 37 e7 [2] 0a }

  condition:
    any of them
}