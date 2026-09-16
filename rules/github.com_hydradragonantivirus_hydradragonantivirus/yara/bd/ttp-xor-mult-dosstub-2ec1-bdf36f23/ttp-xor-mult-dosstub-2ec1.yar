rule TTP_XOR_MULT_DOSStub_2ec1 {
  strings:
    $key_2ec1 = { 7a a9 [2] 0e b1 [2] 49 b3 [2] 0e a2 [2] 40 ae [2] 4c a4 [2] 5b af [2] 40 e1 [2] 7d }

  condition:
    any of them
}