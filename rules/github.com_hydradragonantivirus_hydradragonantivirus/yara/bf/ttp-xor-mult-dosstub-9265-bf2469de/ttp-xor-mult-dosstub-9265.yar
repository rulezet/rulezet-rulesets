rule TTP_XOR_MULT_DOSStub_9265 {
  strings:
    $key_9265 = { c6 0d [2] b2 15 [2] f5 17 [2] b2 06 [2] fc 0a [2] f0 00 [2] e7 0b [2] fc 45 [2] c1 }

  condition:
    any of them
}