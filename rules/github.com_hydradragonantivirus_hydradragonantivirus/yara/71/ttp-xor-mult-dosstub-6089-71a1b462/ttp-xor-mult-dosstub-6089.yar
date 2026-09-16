rule TTP_XOR_MULT_DOSStub_6089 {
  strings:
    $key_6089 = { 34 e1 [2] 40 f9 [2] 07 fb [2] 40 ea [2] 0e e6 [2] 02 ec [2] 15 e7 [2] 0e a9 [2] 33 }

  condition:
    any of them
}