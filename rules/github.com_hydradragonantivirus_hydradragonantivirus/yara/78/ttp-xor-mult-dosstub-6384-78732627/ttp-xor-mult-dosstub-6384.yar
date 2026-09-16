rule TTP_XOR_MULT_DOSStub_6384 {
  strings:
    $key_6384 = { 37 ec [2] 43 f4 [2] 04 f6 [2] 43 e7 [2] 0d eb [2] 01 e1 [2] 16 ea [2] 0d a4 [2] 30 }

  condition:
    any of them
}