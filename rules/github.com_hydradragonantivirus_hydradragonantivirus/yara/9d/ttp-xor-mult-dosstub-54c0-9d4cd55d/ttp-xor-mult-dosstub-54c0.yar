rule TTP_XOR_MULT_DOSStub_54c0 {
  strings:
    $key_54c0 = { 00 a8 [2] 74 b0 [2] 33 b2 [2] 74 a3 [2] 3a af [2] 36 a5 [2] 21 ae [2] 3a e0 [2] 07 }

  condition:
    any of them
}