rule TTP_XOR_MULT_DOSStub_8c82 {
  strings:
    $key_8c82 = { d8 ea [2] ac f2 [2] eb f0 [2] ac e1 [2] e2 ed [2] ee e7 [2] f9 ec [2] e2 a2 [2] df }

  condition:
    any of them
}