rule TTP_XOR_MULT_DOSStub_21c1 {
  strings:
    $key_21c1 = { 75 a9 [2] 01 b1 [2] 46 b3 [2] 01 a2 [2] 4f ae [2] 43 a4 [2] 54 af [2] 4f e1 [2] 72 }

  condition:
    any of them
}