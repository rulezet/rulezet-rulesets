rule TTP_XOR_MULT_DOSStub_902e {
  strings:
    $key_902e = { c4 46 [2] b0 5e [2] f7 5c [2] b0 4d [2] fe 41 [2] f2 4b [2] e5 40 [2] fe 0e [2] c3 }

  condition:
    any of them
}