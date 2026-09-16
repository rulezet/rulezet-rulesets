rule TTP_XOR_MULT_DOSStub_8d5f {
  strings:
    $key_8d5f = { d9 37 [2] ad 2f [2] ea 2d [2] ad 3c [2] e3 30 [2] ef 3a [2] f8 31 [2] e3 7f [2] de }

  condition:
    any of them
}