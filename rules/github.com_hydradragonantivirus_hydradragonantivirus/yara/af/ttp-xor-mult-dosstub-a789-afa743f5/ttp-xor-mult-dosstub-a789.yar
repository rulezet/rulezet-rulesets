rule TTP_XOR_MULT_DOSStub_a789 {
  strings:
    $key_a789 = { f3 e1 [2] 87 f9 [2] c0 fb [2] 87 ea [2] c9 e6 [2] c5 ec [2] d2 e7 [2] c9 a9 [2] f4 }

  condition:
    any of them
}