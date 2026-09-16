rule TTP_XOR_MULT_DOSStub_8d4f {
  strings:
    $key_8d4f = { d9 27 [2] ad 3f [2] ea 3d [2] ad 2c [2] e3 20 [2] ef 2a [2] f8 21 [2] e3 6f [2] de }

  condition:
    any of them
}