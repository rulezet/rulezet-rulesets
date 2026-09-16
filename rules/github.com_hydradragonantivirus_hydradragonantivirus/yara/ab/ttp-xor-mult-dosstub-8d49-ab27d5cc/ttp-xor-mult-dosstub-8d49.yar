rule TTP_XOR_MULT_DOSStub_8d49 {
  strings:
    $key_8d49 = { d9 21 [2] ad 39 [2] ea 3b [2] ad 2a [2] e3 26 [2] ef 2c [2] f8 27 [2] e3 69 [2] de }

  condition:
    any of them
}