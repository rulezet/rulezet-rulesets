rule TTP_XOR_MULT_DOSStub_72c1 {
  strings:
    $key_72c1 = { 26 a9 [2] 52 b1 [2] 15 b3 [2] 52 a2 [2] 1c ae [2] 10 a4 [2] 07 af [2] 1c e1 [2] 21 }

  condition:
    any of them
}