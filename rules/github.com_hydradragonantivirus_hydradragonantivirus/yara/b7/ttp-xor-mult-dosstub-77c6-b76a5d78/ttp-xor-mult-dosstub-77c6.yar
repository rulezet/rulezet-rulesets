rule TTP_XOR_MULT_DOSStub_77c6 {
  strings:
    $key_77c6 = { 23 ae [2] 57 b6 [2] 10 b4 [2] 57 a5 [2] 19 a9 [2] 15 a3 [2] 02 a8 [2] 19 e6 [2] 24 }

  condition:
    any of them
}