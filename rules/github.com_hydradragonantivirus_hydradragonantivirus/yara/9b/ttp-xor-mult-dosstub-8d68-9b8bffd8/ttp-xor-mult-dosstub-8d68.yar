rule TTP_XOR_MULT_DOSStub_8d68 {
  strings:
    $key_8d68 = { d9 00 [2] ad 18 [2] ea 1a [2] ad 0b [2] e3 07 [2] ef 0d [2] f8 06 [2] e3 48 [2] de }

  condition:
    any of them
}