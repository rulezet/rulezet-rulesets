rule TTP_XOR_MULT_DOSStub_9269 {
  strings:
    $key_9269 = { c6 01 [2] b2 19 [2] f5 1b [2] b2 0a [2] fc 06 [2] f0 0c [2] e7 07 [2] fc 49 [2] c1 }

  condition:
    any of them
}