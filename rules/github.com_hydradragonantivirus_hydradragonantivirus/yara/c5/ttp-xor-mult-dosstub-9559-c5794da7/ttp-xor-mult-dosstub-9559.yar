rule TTP_XOR_MULT_DOSStub_9559 {
  strings:
    $key_9559 = { c1 31 [2] b5 29 [2] f2 2b [2] b5 3a [2] fb 36 [2] f7 3c [2] e0 37 [2] fb 79 [2] c6 }

  condition:
    any of them
}