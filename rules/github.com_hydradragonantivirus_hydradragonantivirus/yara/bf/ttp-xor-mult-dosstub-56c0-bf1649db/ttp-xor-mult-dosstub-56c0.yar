rule TTP_XOR_MULT_DOSStub_56c0 {
  strings:
    $key_56c0 = { 02 a8 [2] 76 b0 [2] 31 b2 [2] 76 a3 [2] 38 af [2] 34 a5 [2] 23 ae [2] 38 e0 [2] 05 }

  condition:
    any of them
}