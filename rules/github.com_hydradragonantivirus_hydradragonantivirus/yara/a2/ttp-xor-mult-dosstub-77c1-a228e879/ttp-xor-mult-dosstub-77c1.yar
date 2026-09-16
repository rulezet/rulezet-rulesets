rule TTP_XOR_MULT_DOSStub_77c1 {
  strings:
    $key_77c1 = { 23 a9 [2] 57 b1 [2] 10 b3 [2] 57 a2 [2] 19 ae [2] 15 a4 [2] 02 af [2] 19 e1 [2] 24 }

  condition:
    any of them
}