rule TTP_XOR_MULT_DOSStub_9257 {
  strings:
    $key_9257 = { c6 3f [2] b2 27 [2] f5 25 [2] b2 34 [2] fc 38 [2] f0 32 [2] e7 39 [2] fc 77 [2] c1 }

  condition:
    any of them
}