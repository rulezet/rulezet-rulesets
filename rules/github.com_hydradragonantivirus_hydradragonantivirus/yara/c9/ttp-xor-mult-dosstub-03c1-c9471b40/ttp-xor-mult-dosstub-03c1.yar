rule TTP_XOR_MULT_DOSStub_03c1 {
  strings:
    $key_03c1 = { 57 a9 [2] 23 b1 [2] 64 b3 [2] 23 a2 [2] 6d ae [2] 61 a4 [2] 76 af [2] 6d e1 [2] 50 }

  condition:
    any of them
}