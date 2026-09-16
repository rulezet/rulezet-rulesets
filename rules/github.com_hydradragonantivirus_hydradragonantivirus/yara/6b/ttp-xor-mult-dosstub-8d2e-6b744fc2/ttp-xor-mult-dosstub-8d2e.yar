rule TTP_XOR_MULT_DOSStub_8d2e {
  strings:
    $key_8d2e = { d9 46 [2] ad 5e [2] ea 5c [2] ad 4d [2] e3 41 [2] ef 4b [2] f8 40 [2] e3 0e [2] de }

  condition:
    any of them
}