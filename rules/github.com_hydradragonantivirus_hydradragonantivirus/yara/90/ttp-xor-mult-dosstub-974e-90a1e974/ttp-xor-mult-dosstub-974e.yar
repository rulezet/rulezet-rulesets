rule TTP_XOR_MULT_DOSStub_974e {
  strings:
    $key_974e = { c3 26 [2] b7 3e [2] f0 3c [2] b7 2d [2] f9 21 [2] f5 2b [2] e2 20 [2] f9 6e [2] c4 }

  condition:
    any of them
}