rule TTP_XOR_MULT_DOSStub_9589 {
  strings:
    $key_9589 = { c1 e1 [2] b5 f9 [2] f2 fb [2] b5 ea [2] fb e6 [2] f7 ec [2] e0 e7 [2] fb a9 [2] c6 }

  condition:
    any of them
}