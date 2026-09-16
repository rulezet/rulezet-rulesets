rule TTP_XOR_MULT_DOSStub_9b87 {
  strings:
    $key_9b87 = { cf ef [2] bb f7 [2] fc f5 [2] bb e4 [2] f5 e8 [2] f9 e2 [2] ee e9 [2] f5 a7 [2] c8 }

  condition:
    any of them
}