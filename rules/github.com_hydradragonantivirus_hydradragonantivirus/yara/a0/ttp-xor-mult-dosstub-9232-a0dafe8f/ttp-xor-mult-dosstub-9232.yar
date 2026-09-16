rule TTP_XOR_MULT_DOSStub_9232 {
  strings:
    $key_9232 = { c6 5a [2] b2 42 [2] f5 40 [2] b2 51 [2] fc 5d [2] f0 57 [2] e7 5c [2] fc 12 [2] c1 }

  condition:
    any of them
}