rule TTP_XOR_MULT_DOSStub_9224 {
  strings:
    $key_9224 = { c6 4c [2] b2 54 [2] f5 56 [2] b2 47 [2] fc 4b [2] f0 41 [2] e7 4a [2] fc 04 [2] c1 }

  condition:
    any of them
}