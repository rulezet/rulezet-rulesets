rule TTP_XOR_MULT_DOSStub_33c1 {
  strings:
    $key_33c1 = { 67 a9 [2] 13 b1 [2] 54 b3 [2] 13 a2 [2] 5d ae [2] 51 a4 [2] 46 af [2] 5d e1 [2] 60 }

  condition:
    any of them
}