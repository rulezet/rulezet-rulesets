rule TTP_XOR_MULT_DOSStub_9b84 {
  strings:
    $key_9b84 = { cf ec [2] bb f4 [2] fc f6 [2] bb e7 [2] f5 eb [2] f9 e1 [2] ee ea [2] f5 a4 [2] c8 }

  condition:
    any of them
}