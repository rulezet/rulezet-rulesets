rule TTP_XOR_MULT_DOSStub_45c1 {
  strings:
    $key_45c1 = { 11 a9 [2] 65 b1 [2] 22 b3 [2] 65 a2 [2] 2b ae [2] 27 a4 [2] 30 af [2] 2b e1 [2] 16 }

  condition:
    any of them
}