rule TTP_XOR_MULT_DOSStub_8d0d {
  strings:
    $key_8d0d = { d9 65 [2] ad 7d [2] ea 7f [2] ad 6e [2] e3 62 [2] ef 68 [2] f8 63 [2] e3 2d [2] de }

  condition:
    any of them
}