rule TTP_XOR_MULT_DOSStub_924e {
  strings:
    $key_924e = { c6 26 [2] b2 3e [2] f5 3c [2] b2 2d [2] fc 21 [2] f0 2b [2] e7 20 [2] fc 6e [2] c1 }

  condition:
    any of them
}