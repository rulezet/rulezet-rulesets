rule TTP_XOR_MULT_DOSStub_8172 {
  strings:
    $key_8172 = { d5 1a [2] a1 02 [2] e6 00 [2] a1 11 [2] ef 1d [2] e3 17 [2] f4 1c [2] ef 52 [2] d2 }

  condition:
    any of them
}