rule TTP_XOR_MULT_DOSStub_864e {
  strings:
    $key_864e = { d2 26 [2] a6 3e [2] e1 3c [2] a6 2d [2] e8 21 [2] e4 2b [2] f3 20 [2] e8 6e [2] d5 }

  condition:
    any of them
}