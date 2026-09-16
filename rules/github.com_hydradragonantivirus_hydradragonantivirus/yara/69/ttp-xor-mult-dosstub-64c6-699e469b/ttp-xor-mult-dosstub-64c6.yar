rule TTP_XOR_MULT_DOSStub_64c6 {
  strings:
    $key_64c6 = { 30 ae [2] 44 b6 [2] 03 b4 [2] 44 a5 [2] 0a a9 [2] 06 a3 [2] 11 a8 [2] 0a e6 [2] 37 }

  condition:
    any of them
}