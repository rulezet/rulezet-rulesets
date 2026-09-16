rule TTP_XOR_MULT_DOSStub_8d5e {
  strings:
    $key_8d5e = { d9 36 [2] ad 2e [2] ea 2c [2] ad 3d [2] e3 31 [2] ef 3b [2] f8 30 [2] e3 7e [2] de }

  condition:
    any of them
}