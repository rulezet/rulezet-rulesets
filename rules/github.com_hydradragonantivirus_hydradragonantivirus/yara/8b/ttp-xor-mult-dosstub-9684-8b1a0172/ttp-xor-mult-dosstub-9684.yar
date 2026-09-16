rule TTP_XOR_MULT_DOSStub_9684 {
  strings:
    $key_9684 = { c2 ec [2] b6 f4 [2] f1 f6 [2] b6 e7 [2] f8 eb [2] f4 e1 [2] e3 ea [2] f8 a4 [2] c5 }

  condition:
    any of them
}