rule TTP_XOR_MULT_DOSStub_47c7 {
  strings:
    $key_47c7 = { 13 af [2] 67 b7 [2] 20 b5 [2] 67 a4 [2] 29 a8 [2] 25 a2 [2] 32 a9 [2] 29 e7 [2] 14 }

  condition:
    any of them
}