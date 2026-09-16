rule TTP_XOR_MULT_DOSStub_14c6 {
  strings:
    $key_14c6 = { 40 ae [2] 34 b6 [2] 73 b4 [2] 34 a5 [2] 7a a9 [2] 76 a3 [2] 61 a8 [2] 7a e6 [2] 47 }

  condition:
    any of them
}