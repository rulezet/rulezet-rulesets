rule TTP_XOR_MULT_DOSStub_906e {
  strings:
    $key_906e = { c4 06 [2] b0 1e [2] f7 1c [2] b0 0d [2] fe 01 [2] f2 0b [2] e5 00 [2] fe 4e [2] c3 }

  condition:
    any of them
}