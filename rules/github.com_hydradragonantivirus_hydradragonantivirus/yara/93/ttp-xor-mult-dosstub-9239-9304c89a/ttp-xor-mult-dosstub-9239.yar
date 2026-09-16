rule TTP_XOR_MULT_DOSStub_9239 {
  strings:
    $key_9239 = { c6 51 [2] b2 49 [2] f5 4b [2] b2 5a [2] fc 56 [2] f0 5c [2] e7 57 [2] fc 19 [2] c1 }

  condition:
    any of them
}