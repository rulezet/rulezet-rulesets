rule TTP_XOR_MULT_DOSStub_8498 {
  strings:
    $key_8498 = { d0 f0 [2] a4 e8 [2] e3 ea [2] a4 fb [2] ea f7 [2] e6 fd [2] f1 f6 [2] ea b8 [2] d7 }

  condition:
    any of them
}