rule TTP_XOR_MULT_DOSStub_9289 {
  strings:
    $key_9289 = { c6 e1 [2] b2 f9 [2] f5 fb [2] b2 ea [2] fc e6 [2] f0 ec [2] e7 e7 [2] fc a9 [2] c1 }

  condition:
    any of them
}