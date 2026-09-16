rule TTP_XOR_MULT_DOSStub_a689 {
  strings:
    $key_a689 = { f2 e1 [2] 86 f9 [2] c1 fb [2] 86 ea [2] c8 e6 [2] c4 ec [2] d3 e7 [2] c8 a9 [2] f5 }

  condition:
    any of them
}