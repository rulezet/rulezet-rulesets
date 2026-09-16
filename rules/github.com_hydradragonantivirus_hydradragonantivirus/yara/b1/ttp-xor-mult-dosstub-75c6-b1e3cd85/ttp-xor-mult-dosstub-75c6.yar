rule TTP_XOR_MULT_DOSStub_75c6 {
  strings:
    $key_75c6 = { 21 ae [2] 55 b6 [2] 12 b4 [2] 55 a5 [2] 1b a9 [2] 17 a3 [2] 00 a8 [2] 1b e6 [2] 26 }

  condition:
    any of them
}