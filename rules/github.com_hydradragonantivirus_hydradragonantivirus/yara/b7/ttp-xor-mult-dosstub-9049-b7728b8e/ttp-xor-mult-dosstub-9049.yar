rule TTP_XOR_MULT_DOSStub_9049 {
  strings:
    $key_9049 = { c4 21 [2] b0 39 [2] f7 3b [2] b0 2a [2] fe 26 [2] f2 2c [2] e5 27 [2] fe 69 [2] c3 }

  condition:
    any of them
}