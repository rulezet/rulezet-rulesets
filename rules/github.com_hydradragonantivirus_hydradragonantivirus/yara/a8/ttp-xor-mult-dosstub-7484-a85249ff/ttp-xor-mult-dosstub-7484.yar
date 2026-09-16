rule TTP_XOR_MULT_DOSStub_7484 {
  strings:
    $key_7484 = { 20 ec [2] 54 f4 [2] 13 f6 [2] 54 e7 [2] 1a eb [2] 16 e1 [2] 01 ea [2] 1a a4 [2] 27 }

  condition:
    any of them
}