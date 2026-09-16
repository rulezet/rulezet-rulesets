rule TTP_XOR_MULT_DOSStub_9498 {
  strings:
    $key_9498 = { c0 f0 [2] b4 e8 [2] f3 ea [2] b4 fb [2] fa f7 [2] f6 fd [2] e1 f6 [2] fa b8 [2] c7 }

  condition:
    any of them
}