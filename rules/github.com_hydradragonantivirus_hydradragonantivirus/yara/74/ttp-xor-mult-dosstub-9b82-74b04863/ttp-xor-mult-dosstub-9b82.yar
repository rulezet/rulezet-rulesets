rule TTP_XOR_MULT_DOSStub_9b82 {
  strings:
    $key_9b82 = { cf ea [2] bb f2 [2] fc f0 [2] bb e1 [2] f5 ed [2] f9 e7 [2] ee ec [2] f5 a2 [2] c8 }

  condition:
    any of them
}