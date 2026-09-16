rule TTP_XOR_MULT_DOSStub_74c7 {
  strings:
    $key_74c7 = { 20 af [2] 54 b7 [2] 13 b5 [2] 54 a4 [2] 1a a8 [2] 16 a2 [2] 01 a9 [2] 1a e7 [2] 27 }

  condition:
    any of them
}