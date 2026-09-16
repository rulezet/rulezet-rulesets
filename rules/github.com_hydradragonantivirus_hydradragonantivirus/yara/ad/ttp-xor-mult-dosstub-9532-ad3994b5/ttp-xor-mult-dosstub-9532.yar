rule TTP_XOR_MULT_DOSStub_9532 {
  strings:
    $key_9532 = { c1 5a [2] b5 42 [2] f2 40 [2] b5 51 [2] fb 5d [2] f7 57 [2] e0 5c [2] fb 12 [2] c6 }

  condition:
    any of them
}