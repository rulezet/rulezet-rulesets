rule TTP_XOR_MULT_DOSStub_32c1 {
  strings:
    $key_32c1 = { 66 a9 [2] 12 b1 [2] 55 b3 [2] 12 a2 [2] 5c ae [2] 50 a4 [2] 47 af [2] 5c e1 [2] 61 }

  condition:
    any of them
}