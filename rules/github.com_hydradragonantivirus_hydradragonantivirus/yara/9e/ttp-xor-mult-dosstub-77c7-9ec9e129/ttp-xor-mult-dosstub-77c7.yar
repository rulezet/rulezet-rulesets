rule TTP_XOR_MULT_DOSStub_77c7 {
  strings:
    $key_77c7 = { 23 af [2] 57 b7 [2] 10 b5 [2] 57 a4 [2] 19 a8 [2] 15 a2 [2] 02 a9 [2] 19 e7 [2] 24 }

  condition:
    any of them
}