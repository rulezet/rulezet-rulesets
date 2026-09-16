rule TTP_XOR_MULT_DOSStub_8c89 {
  strings:
    $key_8c89 = { d8 e1 [2] ac f9 [2] eb fb [2] ac ea [2] e2 e6 [2] ee ec [2] f9 e7 [2] e2 a9 [2] df }

  condition:
    any of them
}