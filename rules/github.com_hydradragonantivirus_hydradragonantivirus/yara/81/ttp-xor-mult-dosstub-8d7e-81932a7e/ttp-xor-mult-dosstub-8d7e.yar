rule TTP_XOR_MULT_DOSStub_8d7e {
  strings:
    $key_8d7e = { d9 16 [2] ad 0e [2] ea 0c [2] ad 1d [2] e3 11 [2] ef 1b [2] f8 10 [2] e3 5e [2] de }

  condition:
    any of them
}