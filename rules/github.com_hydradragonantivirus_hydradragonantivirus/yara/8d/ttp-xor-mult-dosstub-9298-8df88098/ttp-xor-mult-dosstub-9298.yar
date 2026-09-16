rule TTP_XOR_MULT_DOSStub_9298 {
  strings:
    $key_9298 = { c6 f0 [2] b2 e8 [2] f5 ea [2] b2 fb [2] fc f7 [2] f0 fd [2] e7 f6 [2] fc b8 [2] c1 }

  condition:
    any of them
}