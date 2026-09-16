rule TTP_XOR_MULT_DOSStub_0089 {
  strings:
    $key_0089 = { 54 e1 [2] 20 f9 [2] 67 fb [2] 20 ea [2] 6e e6 [2] 62 ec [2] 75 e7 [2] 6e a9 [2] 53 }

  condition:
    any of them
}