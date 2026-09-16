rule TTP_XOR_MULT_DOSStub_9278 {
  strings:
    $key_9278 = { c6 10 [2] b2 08 [2] f5 0a [2] b2 1b [2] fc 17 [2] f0 1d [2] e7 16 [2] fc 58 [2] c1 }

  condition:
    any of them
}