rule TTP_XOR_MULT_DOSStub_8dc7 {
  strings:
    $key_8dc7 = { d9 af [2] ad b7 [2] ea b5 [2] ad a4 [2] e3 a8 [2] ef a2 [2] f8 a9 [2] e3 e7 [2] de }

  condition:
    any of them
}