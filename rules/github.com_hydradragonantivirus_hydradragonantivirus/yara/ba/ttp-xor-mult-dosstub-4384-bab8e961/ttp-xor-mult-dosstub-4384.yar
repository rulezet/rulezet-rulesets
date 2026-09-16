rule TTP_XOR_MULT_DOSStub_4384 {
  strings:
    $key_4384 = { 17 ec [2] 63 f4 [2] 24 f6 [2] 63 e7 [2] 2d eb [2] 21 e1 [2] 36 ea [2] 2d a4 [2] 10 }

  condition:
    any of them
}