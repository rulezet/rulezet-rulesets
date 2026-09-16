rule TTP_XOR_MULT_DOSStub_9198 {
  strings:
    $key_9198 = { c5 f0 [2] b1 e8 [2] f6 ea [2] b1 fb [2] ff f7 [2] f3 fd [2] e4 f6 [2] ff b8 [2] c2 }

  condition:
    any of them
}