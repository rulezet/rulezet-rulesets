rule TTP_XOR_MULT_DOSStub_8dd0 {
  strings:
    $key_8dd0 = { d9 b8 [2] ad a0 [2] ea a2 [2] ad b3 [2] e3 bf [2] ef b5 [2] f8 be [2] e3 f0 [2] de }

  condition:
    any of them
}