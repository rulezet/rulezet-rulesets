rule TTP_XOR_MULT_DOSStub_9205 {
  strings:
    $key_9205 = { c6 6d [2] b2 75 [2] f5 77 [2] b2 66 [2] fc 6a [2] f0 60 [2] e7 6b [2] fc 25 [2] c1 }

  condition:
    any of them
}