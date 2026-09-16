rule TTP_XOR_MULT_DOSStub_52c6 {
  strings:
    $key_52c6 = { 06 ae [2] 72 b6 [2] 35 b4 [2] 72 a5 [2] 3c a9 [2] 30 a3 [2] 27 a8 [2] 3c e6 [2] 01 }

  condition:
    any of them
}