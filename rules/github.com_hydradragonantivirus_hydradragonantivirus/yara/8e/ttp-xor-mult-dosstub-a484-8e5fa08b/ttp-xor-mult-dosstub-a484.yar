rule TTP_XOR_MULT_DOSStub_a484 {
  strings:
    $key_a484 = { f0 ec [2] 84 f4 [2] c3 f6 [2] 84 e7 [2] ca eb [2] c6 e1 [2] d1 ea [2] ca a4 [2] f7 }

  condition:
    any of them
}