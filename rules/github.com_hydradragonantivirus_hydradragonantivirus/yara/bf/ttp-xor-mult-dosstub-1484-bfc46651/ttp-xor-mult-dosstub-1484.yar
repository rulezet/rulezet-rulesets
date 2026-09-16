rule TTP_XOR_MULT_DOSStub_1484 {
  strings:
    $key_1484 = { 40 ec [2] 34 f4 [2] 73 f6 [2] 34 e7 [2] 7a eb [2] 76 e1 [2] 61 ea [2] 7a a4 [2] 47 }

  condition:
    any of them
}