rule TTP_XOR_MULT_DOSStub_9276 {
  strings:
    $key_9276 = { c6 1e [2] b2 06 [2] f5 04 [2] b2 15 [2] fc 19 [2] f0 13 [2] e7 18 [2] fc 56 [2] c1 }

  condition:
    any of them
}