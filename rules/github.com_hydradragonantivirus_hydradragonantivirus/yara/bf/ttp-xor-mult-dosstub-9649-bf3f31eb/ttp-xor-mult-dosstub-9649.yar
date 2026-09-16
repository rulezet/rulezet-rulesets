rule TTP_XOR_MULT_DOSStub_9649 {
  strings:
    $key_9649 = { c2 21 [2] b6 39 [2] f1 3b [2] b6 2a [2] f8 26 [2] f4 2c [2] e3 27 [2] f8 69 [2] c5 }

  condition:
    any of them
}