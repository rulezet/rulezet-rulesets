rule TTP_XOR_MULT_DOSStub_9789 {
  strings:
    $key_9789 = { c3 e1 [2] b7 f9 [2] f0 fb [2] b7 ea [2] f9 e6 [2] f5 ec [2] e2 e7 [2] f9 a9 [2] c4 }

  condition:
    any of them
}