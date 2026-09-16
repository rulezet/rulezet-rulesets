rule TTP_XOR_MULT_DOSStub_963e {
  strings:
    $key_963e = { c2 56 [2] b6 4e [2] f1 4c [2] b6 5d [2] f8 51 [2] f4 5b [2] e3 50 [2] f8 1e [2] c5 }

  condition:
    any of them
}