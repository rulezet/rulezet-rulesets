rule TTP_XOR_MULT_DOSStub_40c1 {
  strings:
    $key_40c1 = { 14 a9 [2] 60 b1 [2] 27 b3 [2] 60 a2 [2] 2e ae [2] 22 a4 [2] 35 af [2] 2e e1 [2] 13 }

  condition:
    any of them
}