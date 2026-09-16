rule TTP_XOR_MULT_DOSStub_9674 {
  strings:
    $key_9674 = { c2 1c [2] b6 04 [2] f1 06 [2] b6 17 [2] f8 1b [2] f4 11 [2] e3 1a [2] f8 54 [2] c5 }

  condition:
    any of them
}