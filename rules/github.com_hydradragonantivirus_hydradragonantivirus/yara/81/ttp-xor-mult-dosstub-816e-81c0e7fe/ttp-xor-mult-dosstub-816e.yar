rule TTP_XOR_MULT_DOSStub_816e {
  strings:
    $key_816e = { d5 06 [2] a1 1e [2] e6 1c [2] a1 0d [2] ef 01 [2] e3 0b [2] f4 00 [2] ef 4e [2] d2 }

  condition:
    any of them
}