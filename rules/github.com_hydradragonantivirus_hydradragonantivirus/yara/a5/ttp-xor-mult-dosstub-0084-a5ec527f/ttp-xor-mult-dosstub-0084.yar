rule TTP_XOR_MULT_DOSStub_0084 {
  strings:
    $key_0084 = { 54 ec [2] 20 f4 [2] 67 f6 [2] 20 e7 [2] 6e eb [2] 62 e1 [2] 75 ea [2] 6e a4 [2] 53 }

  condition:
    any of them
}