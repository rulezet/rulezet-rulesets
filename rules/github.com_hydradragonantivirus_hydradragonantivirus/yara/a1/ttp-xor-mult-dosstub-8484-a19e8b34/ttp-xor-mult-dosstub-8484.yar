rule TTP_XOR_MULT_DOSStub_8484 {
  strings:
    $key_8484 = { d0 ec [2] a4 f4 [2] e3 f6 [2] a4 e7 [2] ea eb [2] e6 e1 [2] f1 ea [2] ea a4 [2] d7 }

  condition:
    any of them
}