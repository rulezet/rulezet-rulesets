rule TTP_XOR_MULT_DOSStub_0ec1 {
  strings:
    $key_0ec1 = { 5a a9 [2] 2e b1 [2] 69 b3 [2] 2e a2 [2] 60 ae [2] 6c a4 [2] 7b af [2] 60 e1 [2] 5d }

  condition:
    any of them
}