rule TTP_XOR_MULT_DOSStub_9082 {
  strings:
    $key_9082 = { c4 ea [2] b0 f2 [2] f7 f0 [2] b0 e1 [2] fe ed [2] f2 e7 [2] e5 ec [2] fe a2 [2] c3 }

  condition:
    any of them
}