rule TTP_XOR_MULT_DOSStub_8dde {
  strings:
    $key_8dde = { d9 b6 [2] ad ae [2] ea ac [2] ad bd [2] e3 b1 [2] ef bb [2] f8 b0 [2] e3 fe [2] de }

  condition:
    any of them
}