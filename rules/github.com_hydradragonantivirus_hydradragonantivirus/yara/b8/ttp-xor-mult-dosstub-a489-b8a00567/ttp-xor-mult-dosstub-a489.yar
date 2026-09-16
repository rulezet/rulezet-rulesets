rule TTP_XOR_MULT_DOSStub_a489 {
  strings:
    $key_a489 = { f0 e1 [2] 84 f9 [2] c3 fb [2] 84 ea [2] ca e6 [2] c6 ec [2] d1 e7 [2] ca a9 [2] f7 }

  condition:
    any of them
}