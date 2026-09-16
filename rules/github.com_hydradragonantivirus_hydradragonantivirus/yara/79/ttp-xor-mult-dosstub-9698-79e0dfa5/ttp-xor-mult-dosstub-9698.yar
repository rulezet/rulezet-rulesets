rule TTP_XOR_MULT_DOSStub_9698 {
  strings:
    $key_9698 = { c2 f0 [2] b6 e8 [2] f1 ea [2] b6 fb [2] f8 f7 [2] f4 fd [2] e3 f6 [2] f8 b8 [2] c5 }

  condition:
    any of them
}