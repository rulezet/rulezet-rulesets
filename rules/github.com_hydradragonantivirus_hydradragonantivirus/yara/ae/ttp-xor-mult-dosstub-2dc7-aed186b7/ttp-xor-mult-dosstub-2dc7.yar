rule TTP_XOR_MULT_DOSStub_2dc7 {
  strings:
    $key_2dc7 = { 79 af [2] 0d b7 [2] 4a b5 [2] 0d a4 [2] 43 a8 [2] 4f a2 [2] 58 a9 [2] 43 e7 [2] 7e }

  condition:
    any of them
}