rule TTP_XOR_MULT_DOSStub_9738 {
  strings:
    $key_9738 = { c3 50 [2] b7 48 [2] f0 4a [2] b7 5b [2] f9 57 [2] f5 5d [2] e2 56 [2] f9 18 [2] c4 }

  condition:
    any of them
}