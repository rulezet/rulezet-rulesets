rule TTP_XOR_MULT_DOSStub_8dd3 {
  strings:
    $key_8dd3 = { d9 bb [2] ad a3 [2] ea a1 [2] ad b0 [2] e3 bc [2] ef b6 [2] f8 bd [2] e3 f3 [2] de }

  condition:
    any of them
}