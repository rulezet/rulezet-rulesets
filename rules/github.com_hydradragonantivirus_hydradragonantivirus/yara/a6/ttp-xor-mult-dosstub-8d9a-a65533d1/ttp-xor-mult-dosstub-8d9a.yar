rule TTP_XOR_MULT_DOSStub_8d9a {
  strings:
    $key_8d9a = { d9 f2 [2] ad ea [2] ea e8 [2] ad f9 [2] e3 f5 [2] ef ff [2] f8 f4 [2] e3 ba [2] de }

  condition:
    any of them
}