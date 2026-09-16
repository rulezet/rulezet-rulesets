rule TTP_XOR_MULT_DOSStub_a289 {
  strings:
    $key_a289 = { f6 e1 [2] 82 f9 [2] c5 fb [2] 82 ea [2] cc e6 [2] c0 ec [2] d7 e7 [2] cc a9 [2] f1 }

  condition:
    any of them
}