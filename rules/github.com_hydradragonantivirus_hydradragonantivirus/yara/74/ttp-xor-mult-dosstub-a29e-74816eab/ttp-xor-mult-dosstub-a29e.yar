rule TTP_XOR_MULT_DOSStub_a29e {
  strings:
    $key_a29e = { f6 f6 [2] 82 ee [2] c5 ec [2] 82 fd [2] cc f1 [2] c0 fb [2] d7 f0 [2] cc be [2] f1 }

  condition:
    any of them
}