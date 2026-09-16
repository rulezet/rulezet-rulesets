rule TTP_XOR_MULT_DOSStub_8d2d {
  strings:
    $key_8d2d = { d9 45 [2] ad 5d [2] ea 5f [2] ad 4e [2] e3 42 [2] ef 48 [2] f8 43 [2] e3 0d [2] de }

  condition:
    any of them
}