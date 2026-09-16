rule TTP_XOR_MULT_DOSStub_907e {
  strings:
    $key_907e = { c4 16 [2] b0 0e [2] f7 0c [2] b0 1d [2] fe 11 [2] f2 1b [2] e5 10 [2] fe 5e [2] c3 }

  condition:
    any of them
}