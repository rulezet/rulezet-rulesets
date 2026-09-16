rule TTP_XOR_MULT_DOSStub_8ddd {
  strings:
    $key_8ddd = { d9 b5 [2] ad ad [2] ea af [2] ad be [2] e3 b2 [2] ef b8 [2] f8 b3 [2] e3 fd [2] de }

  condition:
    any of them
}