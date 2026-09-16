rule TTP_XOR_MULT_DOSStub_977e {
  strings:
    $key_977e = { c3 16 [2] b7 0e [2] f0 0c [2] b7 1d [2] f9 11 [2] f5 1b [2] e2 10 [2] f9 5e [2] c4 }

  condition:
    any of them
}