rule TTP_XOR_MULT_DOSStub_9749 {
  strings:
    $key_9749 = { c3 21 [2] b7 39 [2] f0 3b [2] b7 2a [2] f9 26 [2] f5 2c [2] e2 27 [2] f9 69 [2] c4 }

  condition:
    any of them
}