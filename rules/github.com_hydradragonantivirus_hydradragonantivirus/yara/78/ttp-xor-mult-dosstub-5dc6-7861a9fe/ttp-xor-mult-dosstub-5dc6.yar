rule TTP_XOR_MULT_DOSStub_5dc6 {
  strings:
    $key_5dc6 = { 09 ae [2] 7d b6 [2] 3a b4 [2] 7d a5 [2] 33 a9 [2] 3f a3 [2] 28 a8 [2] 33 e6 [2] 0e }

  condition:
    any of them
}