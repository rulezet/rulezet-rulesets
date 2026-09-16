rule TTP_XOR_MULT_DOSStub_5ec1 {
  strings:
    $key_5ec1 = { 0a a9 [2] 7e b1 [2] 39 b3 [2] 7e a2 [2] 30 ae [2] 3c a4 [2] 2b af [2] 30 e1 [2] 0d }

  condition:
    any of them
}