rule TTP_XOR_MULT_DOSStub_23c1 {
  strings:
    $key_23c1 = { 77 a9 [2] 03 b1 [2] 44 b3 [2] 03 a2 [2] 4d ae [2] 41 a4 [2] 56 af [2] 4d e1 [2] 70 }

  condition:
    any of them
}