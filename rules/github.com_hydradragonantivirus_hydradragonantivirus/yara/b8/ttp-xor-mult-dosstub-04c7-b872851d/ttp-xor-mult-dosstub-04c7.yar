rule TTP_XOR_MULT_DOSStub_04c7 {
  strings:
    $key_04c7 = { 50 af [2] 24 b7 [2] 63 b5 [2] 24 a4 [2] 6a a8 [2] 66 a2 [2] 71 a9 [2] 6a e7 [2] 57 }

  condition:
    any of them
}