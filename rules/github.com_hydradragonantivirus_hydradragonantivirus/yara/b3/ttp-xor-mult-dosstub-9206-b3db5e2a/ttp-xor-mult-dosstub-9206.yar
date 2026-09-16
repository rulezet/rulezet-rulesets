rule TTP_XOR_MULT_DOSStub_9206 {
  strings:
    $key_9206 = { c6 6e [2] b2 76 [2] f5 74 [2] b2 65 [2] fc 69 [2] f0 63 [2] e7 68 [2] fc 26 [2] c1 }

  condition:
    any of them
}