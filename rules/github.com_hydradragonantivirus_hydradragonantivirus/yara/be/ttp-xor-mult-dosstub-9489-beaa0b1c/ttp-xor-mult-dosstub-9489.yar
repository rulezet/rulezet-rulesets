rule TTP_XOR_MULT_DOSStub_9489 {
  strings:
    $key_9489 = { c0 e1 [2] b4 f9 [2] f3 fb [2] b4 ea [2] fa e6 [2] f6 ec [2] e1 e7 [2] fa a9 [2] c7 }

  condition:
    any of them
}