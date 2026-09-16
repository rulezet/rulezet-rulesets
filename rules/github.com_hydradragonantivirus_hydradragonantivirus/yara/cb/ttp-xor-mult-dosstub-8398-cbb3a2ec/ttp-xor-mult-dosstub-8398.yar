rule TTP_XOR_MULT_DOSStub_8398 {
  strings:
    $key_8398 = { d7 f0 [2] a3 e8 [2] e4 ea [2] a3 fb [2] ed f7 [2] e1 fd [2] f6 f6 [2] ed b8 [2] d0 }

  condition:
    any of them
}