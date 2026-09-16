rule TTP_XOR_MULT_DOSStub_64c0 {
  strings:
    $key_64c0 = { 30 a8 [2] 44 b0 [2] 03 b2 [2] 44 a3 [2] 0a af [2] 06 a5 [2] 11 ae [2] 0a e0 [2] 37 }

  condition:
    any of them
}