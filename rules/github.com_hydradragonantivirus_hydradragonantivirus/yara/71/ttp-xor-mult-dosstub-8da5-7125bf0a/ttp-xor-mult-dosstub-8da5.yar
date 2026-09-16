rule TTP_XOR_MULT_DOSStub_8da5 {
  strings:
    $key_8da5 = { d9 cd [2] ad d5 [2] ea d7 [2] ad c6 [2] e3 ca [2] ef c0 [2] f8 cb [2] e3 85 [2] de }

  condition:
    any of them
}