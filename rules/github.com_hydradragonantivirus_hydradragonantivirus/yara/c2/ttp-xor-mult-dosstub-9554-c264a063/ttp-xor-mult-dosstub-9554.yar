rule TTP_XOR_MULT_DOSStub_9554 {
  strings:
    $key_9554 = { c1 3c [2] b5 24 [2] f2 26 [2] b5 37 [2] fb 3b [2] f7 31 [2] e0 3a [2] fb 74 [2] c6 }

  condition:
    any of them
}