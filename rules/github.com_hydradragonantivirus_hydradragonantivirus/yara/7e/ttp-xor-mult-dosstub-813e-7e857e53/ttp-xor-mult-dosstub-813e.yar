rule TTP_XOR_MULT_DOSStub_813e {
  strings:
    $key_813e = { d5 56 [2] a1 4e [2] e6 4c [2] a1 5d [2] ef 51 [2] e3 5b [2] f4 50 [2] ef 1e [2] d2 }

  condition:
    any of them
}