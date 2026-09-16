rule TTP_XOR_MULT_DOSStub_8d72 {
  strings:
    $key_8d72 = { d9 1a [2] ad 02 [2] ea 00 [2] ad 11 [2] e3 1d [2] ef 17 [2] f8 1c [2] e3 52 [2] de }

  condition:
    any of them
}