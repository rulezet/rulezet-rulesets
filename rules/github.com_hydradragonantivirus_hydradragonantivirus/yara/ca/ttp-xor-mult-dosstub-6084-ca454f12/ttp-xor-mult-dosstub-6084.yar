rule TTP_XOR_MULT_DOSStub_6084 {
  strings:
    $key_6084 = { 34 ec [2] 40 f4 [2] 07 f6 [2] 40 e7 [2] 0e eb [2] 02 e1 [2] 15 ea [2] 0e a4 [2] 33 }

  condition:
    any of them
}