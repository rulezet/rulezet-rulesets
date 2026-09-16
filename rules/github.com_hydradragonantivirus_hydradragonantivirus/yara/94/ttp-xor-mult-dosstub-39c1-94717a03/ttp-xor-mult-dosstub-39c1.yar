rule TTP_XOR_MULT_DOSStub_39c1 {
  strings:
    $key_39c1 = { 6d a9 [2] 19 b1 [2] 5e b3 [2] 19 a2 [2] 57 ae [2] 5b a4 [2] 4c af [2] 57 e1 [2] 6a }

  condition:
    any of them
}