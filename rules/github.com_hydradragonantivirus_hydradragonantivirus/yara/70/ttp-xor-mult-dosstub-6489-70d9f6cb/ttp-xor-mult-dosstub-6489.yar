rule TTP_XOR_MULT_DOSStub_6489 {
  strings:
    $key_6489 = { 30 e1 [2] 44 f9 [2] 03 fb [2] 44 ea [2] 0a e6 [2] 06 ec [2] 11 e7 [2] 0a a9 [2] 37 }

  condition:
    any of them
}