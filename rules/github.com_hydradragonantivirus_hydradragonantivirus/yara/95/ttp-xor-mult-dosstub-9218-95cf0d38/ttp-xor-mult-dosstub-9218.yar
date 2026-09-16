rule TTP_XOR_MULT_DOSStub_9218 {
  strings:
    $key_9218 = { c6 70 [2] b2 68 [2] f5 6a [2] b2 7b [2] fc 77 [2] f0 7d [2] e7 76 [2] fc 38 [2] c1 }

  condition:
    any of them
}