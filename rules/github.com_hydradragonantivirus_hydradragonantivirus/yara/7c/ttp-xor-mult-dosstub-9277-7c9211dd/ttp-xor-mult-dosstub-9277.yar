rule TTP_XOR_MULT_DOSStub_9277 {
  strings:
    $key_9277 = { c6 1f [2] b2 07 [2] f5 05 [2] b2 14 [2] fc 18 [2] f0 12 [2] e7 19 [2] fc 57 [2] c1 }

  condition:
    any of them
}