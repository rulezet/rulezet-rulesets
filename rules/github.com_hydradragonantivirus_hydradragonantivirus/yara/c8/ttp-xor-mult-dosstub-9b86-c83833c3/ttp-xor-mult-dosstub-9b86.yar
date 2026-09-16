rule TTP_XOR_MULT_DOSStub_9b86 {
  strings:
    $key_9b86 = { cf ee [2] bb f6 [2] fc f4 [2] bb e5 [2] f5 e9 [2] f9 e3 [2] ee e8 [2] f5 a6 [2] c8 }

  condition:
    any of them
}