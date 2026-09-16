rule TTP_XOR_MULT_DOSStub_8da9 {
  strings:
    $key_8da9 = { d9 c1 [2] ad d9 [2] ea db [2] ad ca [2] e3 c6 [2] ef cc [2] f8 c7 [2] e3 89 [2] de }

  condition:
    any of them
}