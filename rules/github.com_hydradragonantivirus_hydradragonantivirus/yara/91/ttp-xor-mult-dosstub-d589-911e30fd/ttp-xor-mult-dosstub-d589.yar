rule TTP_XOR_MULT_DOSStub_d589 {
  strings:
    $key_d589 = { 81 e1 [2] f5 f9 [2] b2 fb [2] f5 ea [2] bb e6 [2] b7 ec [2] a0 e7 [2] bb a9 [2] 86 }

  condition:
    any of them
}