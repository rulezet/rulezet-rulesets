rule TTP_XOR_MULT_DOSStub_8d0e {
  strings:
    $key_8d0e = { d9 66 [2] ad 7e [2] ea 7c [2] ad 6d [2] e3 61 [2] ef 6b [2] f8 60 [2] e3 2e [2] de }

  condition:
    any of them
}