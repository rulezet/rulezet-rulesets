rule TTP_XOR_MULT_DOSStub_8dc8 {
  strings:
    $key_8dc8 = { d9 a0 [2] ad b8 [2] ea ba [2] ad ab [2] e3 a7 [2] ef ad [2] f8 a6 [2] e3 e8 [2] de }

  condition:
    any of them
}