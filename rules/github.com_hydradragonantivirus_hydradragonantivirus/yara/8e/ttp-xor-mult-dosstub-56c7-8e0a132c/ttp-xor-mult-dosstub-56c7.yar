rule TTP_XOR_MULT_DOSStub_56c7 {
  strings:
    $key_56c7 = { 02 af [2] 76 b7 [2] 31 b5 [2] 76 a4 [2] 38 a8 [2] 34 a2 [2] 23 a9 [2] 38 e7 [2] 05 }

  condition:
    any of them
}