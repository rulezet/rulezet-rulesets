rule TTP_XOR_MULT_DOSStub_9784 {
  strings:
    $key_9784 = { c3 ec [2] b7 f4 [2] f0 f6 [2] b7 e7 [2] f9 eb [2] f5 e1 [2] e2 ea [2] f9 a4 [2] c4 }

  condition:
    any of them
}