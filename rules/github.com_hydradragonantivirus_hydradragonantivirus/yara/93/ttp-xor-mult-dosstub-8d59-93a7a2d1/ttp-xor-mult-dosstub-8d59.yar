rule TTP_XOR_MULT_DOSStub_8d59 {
  strings:
    $key_8d59 = { d9 31 [2] ad 29 [2] ea 2b [2] ad 3a [2] e3 36 [2] ef 3c [2] f8 37 [2] e3 79 [2] de }

  condition:
    any of them
}