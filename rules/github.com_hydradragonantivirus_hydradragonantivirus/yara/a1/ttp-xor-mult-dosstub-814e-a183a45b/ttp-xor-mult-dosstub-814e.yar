rule TTP_XOR_MULT_DOSStub_814e {
  strings:
    $key_814e = { d5 26 [2] a1 3e [2] e6 3c [2] a1 2d [2] ef 21 [2] e3 2b [2] f4 20 [2] ef 6e [2] d2 }

  condition:
    any of them
}