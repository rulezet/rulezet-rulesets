rule TTP_XOR_MULT_DOSStub_52c0 {
  strings:
    $key_52c0 = { 06 a8 [2] 72 b0 [2] 35 b2 [2] 72 a3 [2] 3c af [2] 30 a5 [2] 27 ae [2] 3c e0 [2] 01 }

  condition:
    any of them
}