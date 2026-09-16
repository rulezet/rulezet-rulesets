rule TTP_XOR_MULT_DOSStub_49c1 {
  strings:
    $key_49c1 = { 1d a9 [2] 69 b1 [2] 2e b3 [2] 69 a2 [2] 27 ae [2] 2b a4 [2] 3c af [2] 27 e1 [2] 1a }

  condition:
    any of them
}