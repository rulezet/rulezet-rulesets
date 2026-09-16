rule TTP_XOR_MULT_DOSStub_9264 {
  strings:
    $key_9264 = { c6 0c [2] b2 14 [2] f5 16 [2] b2 07 [2] fc 0b [2] f0 01 [2] e7 0a [2] fc 44 [2] c1 }

  condition:
    any of them
}