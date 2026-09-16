rule TTP_XOR_MULT_DOSStub_9196 {
  strings:
    $key_9196 = { c5 fe [2] b1 e6 [2] f6 e4 [2] b1 f5 [2] ff f9 [2] f3 f3 [2] e4 f8 [2] ff b6 [2] c2 }

  condition:
    any of them
}