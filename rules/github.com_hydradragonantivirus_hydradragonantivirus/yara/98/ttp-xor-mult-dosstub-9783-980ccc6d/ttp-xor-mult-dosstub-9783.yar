rule TTP_XOR_MULT_DOSStub_9783 {
  strings:
    $key_9783 = { c3 eb [2] b7 f3 [2] f0 f1 [2] b7 e0 [2] f9 ec [2] f5 e6 [2] e2 ed [2] f9 a3 [2] c4 }

  condition:
    any of them
}