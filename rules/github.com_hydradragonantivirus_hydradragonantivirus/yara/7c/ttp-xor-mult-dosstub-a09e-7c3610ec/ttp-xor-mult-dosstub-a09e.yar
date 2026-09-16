rule TTP_XOR_MULT_DOSStub_a09e {
  strings:
    $key_a09e = { f4 f6 [2] 80 ee [2] c7 ec [2] 80 fd [2] ce f1 [2] c2 fb [2] d5 f0 [2] ce be [2] f3 }

  condition:
    any of them
}