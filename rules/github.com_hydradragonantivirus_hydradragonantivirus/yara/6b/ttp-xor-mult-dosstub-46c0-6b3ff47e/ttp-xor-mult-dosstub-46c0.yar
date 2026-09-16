rule TTP_XOR_MULT_DOSStub_46c0 {
  strings:
    $key_46c0 = { 12 a8 [2] 66 b0 [2] 21 b2 [2] 66 a3 [2] 28 af [2] 24 a5 [2] 33 ae [2] 28 e0 [2] 15 }

  condition:
    any of them
}