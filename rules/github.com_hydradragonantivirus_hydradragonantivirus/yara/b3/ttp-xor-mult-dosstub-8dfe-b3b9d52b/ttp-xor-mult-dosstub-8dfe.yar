rule TTP_XOR_MULT_DOSStub_8dfe {
  strings:
    $key_8dfe = { d9 96 [2] ad 8e [2] ea 8c [2] ad 9d [2] e3 91 [2] ef 9b [2] f8 90 [2] e3 de [2] de }

  condition:
    any of them
}