rule TTP_XOR_MULT_DOSStub_3484 {
  strings:
    $key_3484 = { 60 ec [2] 14 f4 [2] 53 f6 [2] 14 e7 [2] 5a eb [2] 56 e1 [2] 41 ea [2] 5a a4 [2] 67 }

  condition:
    any of them
}