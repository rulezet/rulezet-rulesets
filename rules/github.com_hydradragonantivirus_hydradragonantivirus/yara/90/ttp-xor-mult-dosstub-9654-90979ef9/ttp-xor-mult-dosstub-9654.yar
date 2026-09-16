rule TTP_XOR_MULT_DOSStub_9654 {
  strings:
    $key_9654 = { c2 3c [2] b6 24 [2] f1 26 [2] b6 37 [2] f8 3b [2] f4 31 [2] e3 3a [2] f8 74 [2] c5 }

  condition:
    any of them
}