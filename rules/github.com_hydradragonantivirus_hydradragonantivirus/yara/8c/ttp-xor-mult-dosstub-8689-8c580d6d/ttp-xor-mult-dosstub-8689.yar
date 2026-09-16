rule TTP_XOR_MULT_DOSStub_8689 {
  strings:
    $key_8689 = { d2 e1 [2] a6 f9 [2] e1 fb [2] a6 ea [2] e8 e6 [2] e4 ec [2] f3 e7 [2] e8 a9 [2] d5 }

  condition:
    any of them
}