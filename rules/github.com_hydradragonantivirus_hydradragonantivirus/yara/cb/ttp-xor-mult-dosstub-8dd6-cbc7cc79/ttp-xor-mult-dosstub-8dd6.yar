rule TTP_XOR_MULT_DOSStub_8dd6 {
  strings:
    $key_8dd6 = { d9 be [2] ad a6 [2] ea a4 [2] ad b5 [2] e3 b9 [2] ef b3 [2] f8 b8 [2] e3 f6 [2] de }

  condition:
    any of them
}