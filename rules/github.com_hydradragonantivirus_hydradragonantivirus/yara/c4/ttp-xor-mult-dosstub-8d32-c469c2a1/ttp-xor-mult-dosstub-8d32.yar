rule TTP_XOR_MULT_DOSStub_8d32 {
  strings:
    $key_8d32 = { d9 5a [2] ad 42 [2] ea 40 [2] ad 51 [2] e3 5d [2] ef 57 [2] f8 5c [2] e3 12 [2] de }

  condition:
    any of them
}