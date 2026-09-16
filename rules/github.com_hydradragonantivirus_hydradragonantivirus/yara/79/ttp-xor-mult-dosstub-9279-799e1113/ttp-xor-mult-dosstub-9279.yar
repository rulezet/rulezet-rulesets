rule TTP_XOR_MULT_DOSStub_9279 {
  strings:
    $key_9279 = { c6 11 [2] b2 09 [2] f5 0b [2] b2 1a [2] fc 16 [2] f0 1c [2] e7 17 [2] fc 59 [2] c1 }

  condition:
    any of them
}