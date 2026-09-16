rule TTP_XOR_MULT_DOSStub_62c1 {
  strings:
    $key_62c1 = { 36 a9 [2] 42 b1 [2] 05 b3 [2] 42 a2 [2] 0c ae [2] 00 a4 [2] 17 af [2] 0c e1 [2] 31 }

  condition:
    any of them
}