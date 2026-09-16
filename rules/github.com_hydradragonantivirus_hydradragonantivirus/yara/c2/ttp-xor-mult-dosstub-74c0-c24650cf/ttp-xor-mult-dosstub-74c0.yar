rule TTP_XOR_MULT_DOSStub_74c0 {
  strings:
    $key_74c0 = { 20 a8 [2] 54 b0 [2] 13 b2 [2] 54 a3 [2] 1a af [2] 16 a5 [2] 01 ae [2] 1a e0 [2] 27 }

  condition:
    any of them
}