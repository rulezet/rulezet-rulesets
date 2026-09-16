rule TTP_XOR_MULT_DOSStub_67c7 {
  strings:
    $key_67c7 = { 33 af [2] 47 b7 [2] 00 b5 [2] 47 a4 [2] 09 a8 [2] 05 a2 [2] 12 a9 [2] 09 e7 [2] 34 }

  condition:
    any of them
}