rule TTP_XOR_MULT_DOSStub_9798 {
  strings:
    $key_9798 = { c3 f0 [2] b7 e8 [2] f0 ea [2] b7 fb [2] f9 f7 [2] f5 fd [2] e2 f6 [2] f9 b8 [2] c4 }

  condition:
    any of them
}