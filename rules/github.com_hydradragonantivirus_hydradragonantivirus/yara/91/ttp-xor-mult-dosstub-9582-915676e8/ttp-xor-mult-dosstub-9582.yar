rule TTP_XOR_MULT_DOSStub_9582 {
  strings:
    $key_9582 = { c1 ea [2] b5 f2 [2] f2 f0 [2] b5 e1 [2] fb ed [2] f7 e7 [2] e0 ec [2] fb a2 [2] c6 }

  condition:
    any of them
}