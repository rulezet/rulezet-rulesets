rule TTP_XOR_MULT_DOSStub_8489 {
  strings:
    $key_8489 = { d0 e1 [2] a4 f9 [2] e3 fb [2] a4 ea [2] ea e6 [2] e6 ec [2] f1 e7 [2] ea a9 [2] d7 }

  condition:
    any of them
}