rule TTP_XOR_MULT_DOSStub_f5c1 {
  strings:
    $key_f5c1 = { a1 a9 [2] d5 b1 [2] 92 b3 [2] d5 a2 [2] 9b ae [2] 97 a4 [2] 80 af [2] 9b e1 [2] a6 }

  condition:
    any of them
}