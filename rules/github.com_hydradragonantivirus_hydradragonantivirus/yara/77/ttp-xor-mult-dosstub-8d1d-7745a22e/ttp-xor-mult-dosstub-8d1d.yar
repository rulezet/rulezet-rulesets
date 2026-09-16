rule TTP_XOR_MULT_DOSStub_8d1d {
  strings:
    $key_8d1d = { d9 75 [2] ad 6d [2] ea 6f [2] ad 7e [2] e3 72 [2] ef 78 [2] f8 73 [2] e3 3d [2] de }

  condition:
    any of them
}