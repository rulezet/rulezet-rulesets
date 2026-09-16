rule TTP_XOR_MULT_DOSStub_14c0 {
  strings:
    $key_14c0 = { 40 a8 [2] 34 b0 [2] 73 b2 [2] 34 a3 [2] 7a af [2] 76 a5 [2] 61 ae [2] 7a e0 [2] 47 }

  condition:
    any of them
}