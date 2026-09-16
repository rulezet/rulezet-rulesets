rule TTP_XOR_MULT_DOSStub_5dc7 {
  strings:
    $key_5dc7 = { 09 af [2] 7d b7 [2] 3a b5 [2] 7d a4 [2] 33 a8 [2] 3f a2 [2] 28 a9 [2] 33 e7 [2] 0e }

  condition:
    any of them
}