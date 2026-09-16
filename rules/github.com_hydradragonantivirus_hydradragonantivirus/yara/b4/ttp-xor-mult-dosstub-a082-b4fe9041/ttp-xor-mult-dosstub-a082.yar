rule TTP_XOR_MULT_DOSStub_a082 {
  strings:
    $key_a082 = { f4 ea [2] 80 f2 [2] c7 f0 [2] 80 e1 [2] ce ed [2] c2 e7 [2] d5 ec [2] ce a2 [2] f3 }

  condition:
    any of them
}