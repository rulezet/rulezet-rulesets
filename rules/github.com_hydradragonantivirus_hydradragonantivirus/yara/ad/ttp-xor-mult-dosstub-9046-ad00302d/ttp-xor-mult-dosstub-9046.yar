rule TTP_XOR_MULT_DOSStub_9046 {
  strings:
    $key_9046 = { c4 2e [2] b0 36 [2] f7 34 [2] b0 25 [2] fe 29 [2] f2 23 [2] e5 28 [2] fe 66 [2] c3 }

  condition:
    any of them
}