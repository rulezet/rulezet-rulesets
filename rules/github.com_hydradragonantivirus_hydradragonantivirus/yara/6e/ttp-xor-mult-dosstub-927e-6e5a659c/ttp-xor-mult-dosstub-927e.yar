rule TTP_XOR_MULT_DOSStub_927e {
  strings:
    $key_927e = { c6 16 [2] b2 0e [2] f5 0c [2] b2 1d [2] fc 11 [2] f0 1b [2] e7 10 [2] fc 5e [2] c1 }

  condition:
    any of them
}