rule TTP_XOR_MULT_DOSStub_3489 {
  strings:
    $key_3489 = { 60 e1 [2] 14 f9 [2] 53 fb [2] 14 ea [2] 5a e6 [2] 56 ec [2] 41 e7 [2] 5a a9 [2] 67 }

  condition:
    any of them
}