rule TTP_XOR_MULT_DOSStub_8dca {
  strings:
    $key_8dca = { d9 a2 [2] ad ba [2] ea b8 [2] ad a9 [2] e3 a5 [2] ef af [2] f8 a4 [2] e3 ea [2] de }

  condition:
    any of them
}