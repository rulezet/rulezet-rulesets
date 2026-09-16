rule TTP_XOR_MULT_DOSStub_9729 {
  strings:
    $key_9729 = { c3 41 [2] b7 59 [2] f0 5b [2] b7 4a [2] f9 46 [2] f5 4c [2] e2 47 [2] f9 09 [2] c4 }

  condition:
    any of them
}