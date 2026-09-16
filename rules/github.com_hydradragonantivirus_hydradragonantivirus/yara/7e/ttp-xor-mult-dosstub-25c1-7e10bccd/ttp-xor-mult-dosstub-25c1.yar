rule TTP_XOR_MULT_DOSStub_25c1 {
  strings:
    $key_25c1 = { 71 a9 [2] 05 b1 [2] 42 b3 [2] 05 a2 [2] 4b ae [2] 47 a4 [2] 50 af [2] 4b e1 [2] 76 }

  condition:
    any of them
}