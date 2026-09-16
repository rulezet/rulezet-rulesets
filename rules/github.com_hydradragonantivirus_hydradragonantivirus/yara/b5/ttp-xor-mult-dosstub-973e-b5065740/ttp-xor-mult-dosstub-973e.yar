rule TTP_XOR_MULT_DOSStub_973e {
  strings:
    $key_973e = { c3 56 [2] b7 4e [2] f0 4c [2] b7 5d [2] f9 51 [2] f5 5b [2] e2 50 [2] f9 1e [2] c4 }

  condition:
    any of them
}