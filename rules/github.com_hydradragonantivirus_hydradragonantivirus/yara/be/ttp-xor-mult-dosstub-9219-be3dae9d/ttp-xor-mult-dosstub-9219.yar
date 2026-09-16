rule TTP_XOR_MULT_DOSStub_9219 {
  strings:
    $key_9219 = { c6 71 [2] b2 69 [2] f5 6b [2] b2 7a [2] fc 76 [2] f0 7c [2] e7 77 [2] fc 39 [2] c1 }

  condition:
    any of them
}