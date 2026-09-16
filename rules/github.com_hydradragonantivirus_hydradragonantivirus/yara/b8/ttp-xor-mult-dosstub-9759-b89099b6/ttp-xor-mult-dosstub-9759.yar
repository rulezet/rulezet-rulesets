rule TTP_XOR_MULT_DOSStub_9759 {
  strings:
    $key_9759 = { c3 31 [2] b7 29 [2] f0 2b [2] b7 3a [2] f9 36 [2] f5 3c [2] e2 37 [2] f9 79 [2] c4 }

  condition:
    any of them
}