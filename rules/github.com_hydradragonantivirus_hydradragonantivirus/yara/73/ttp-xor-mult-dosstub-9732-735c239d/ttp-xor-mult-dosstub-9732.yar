rule TTP_XOR_MULT_DOSStub_9732 {
  strings:
    $key_9732 = { c3 5a [2] b7 42 [2] f0 40 [2] b7 51 [2] f9 5d [2] f5 57 [2] e2 5c [2] f9 12 [2] c4 }

  condition:
    any of them
}