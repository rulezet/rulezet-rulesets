rule TTP_XOR_MULT_DOSStub_8d52 {
  strings:
    $key_8d52 = { d9 3a [2] ad 22 [2] ea 20 [2] ad 31 [2] e3 3d [2] ef 37 [2] f8 3c [2] e3 72 [2] de }

  condition:
    any of them
}