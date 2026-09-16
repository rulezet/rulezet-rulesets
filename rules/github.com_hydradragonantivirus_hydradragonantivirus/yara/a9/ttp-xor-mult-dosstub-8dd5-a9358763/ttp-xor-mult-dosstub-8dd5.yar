rule TTP_XOR_MULT_DOSStub_8dd5 {
  strings:
    $key_8dd5 = { d9 bd [2] ad a5 [2] ea a7 [2] ad b6 [2] e3 ba [2] ef b0 [2] f8 bb [2] e3 f5 [2] de }

  condition:
    any of them
}