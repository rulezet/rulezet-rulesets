rule TTP_XOR_MULT_DOSStub_9184 {
  strings:
    $key_9184 = { c5 ec [2] b1 f4 [2] f6 f6 [2] b1 e7 [2] ff eb [2] f3 e1 [2] e4 ea [2] ff a4 [2] c2 }

  condition:
    any of them
}