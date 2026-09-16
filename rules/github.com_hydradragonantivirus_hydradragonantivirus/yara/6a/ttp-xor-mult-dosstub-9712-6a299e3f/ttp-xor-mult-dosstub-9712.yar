rule TTP_XOR_MULT_DOSStub_9712 {
  strings:
    $key_9712 = { c3 7a [2] b7 62 [2] f0 60 [2] b7 71 [2] f9 7d [2] f5 77 [2] e2 7c [2] f9 32 [2] c4 }

  condition:
    any of them
}