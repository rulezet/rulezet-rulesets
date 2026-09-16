rule TTP_XOR_MULT_DOSStub_8dd4 {
  strings:
    $key_8dd4 = { d9 bc [2] ad a4 [2] ea a6 [2] ad b7 [2] e3 bb [2] ef b1 [2] f8 ba [2] e3 f4 [2] de }

  condition:
    any of them
}