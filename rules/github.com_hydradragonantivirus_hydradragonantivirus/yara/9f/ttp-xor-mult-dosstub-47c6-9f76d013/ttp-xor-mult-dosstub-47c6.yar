rule TTP_XOR_MULT_DOSStub_47c6 {
  strings:
    $key_47c6 = { 13 ae [2] 67 b6 [2] 20 b4 [2] 67 a5 [2] 29 a9 [2] 25 a3 [2] 32 a8 [2] 29 e6 [2] 14 }

  condition:
    any of them
}