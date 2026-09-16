rule TTP_XOR_MULT_DOSStub_8dc6 {
  strings:
    $key_8dc6 = { d9 ae [2] ad b6 [2] ea b4 [2] ad a5 [2] e3 a9 [2] ef a3 [2] f8 a8 [2] e3 e6 [2] de }

  condition:
    any of them
}