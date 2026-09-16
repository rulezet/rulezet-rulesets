rule TTP_XOR_MULT_DOSStub_9241 {
  strings:
    $key_9241 = { c6 29 [2] b2 31 [2] f5 33 [2] b2 22 [2] fc 2e [2] f0 24 [2] e7 2f [2] fc 61 [2] c1 }

  condition:
    any of them
}