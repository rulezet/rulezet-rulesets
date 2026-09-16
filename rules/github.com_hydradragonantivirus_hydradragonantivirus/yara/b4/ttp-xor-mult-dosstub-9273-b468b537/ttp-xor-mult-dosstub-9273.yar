rule TTP_XOR_MULT_DOSStub_9273 {
  strings:
    $key_9273 = { c6 1b [2] b2 03 [2] f5 01 [2] b2 10 [2] fc 1c [2] f0 16 [2] e7 1d [2] fc 53 [2] c1 }

  condition:
    any of them
}