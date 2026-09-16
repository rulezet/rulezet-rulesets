rule TTP_XOR_MULT_DOSStub_9274 {
  strings:
    $key_9274 = { c6 1c [2] b2 04 [2] f5 06 [2] b2 17 [2] fc 1b [2] f0 11 [2] e7 1a [2] fc 54 [2] c1 }

  condition:
    any of them
}