rule TTP_XOR_MULT_DOSStub_903e {
  strings:
    $key_903e = { c4 56 [2] b0 4e [2] f7 4c [2] b0 5d [2] fe 51 [2] f2 5b [2] e5 50 [2] fe 1e [2] c3 }

  condition:
    any of them
}