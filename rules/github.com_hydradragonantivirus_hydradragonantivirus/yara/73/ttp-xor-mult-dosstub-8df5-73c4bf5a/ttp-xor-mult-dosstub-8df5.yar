rule TTP_XOR_MULT_DOSStub_8df5 {
  strings:
    $key_8df5 = { d9 9d [2] ad 85 [2] ea 87 [2] ad 96 [2] e3 9a [2] ef 90 [2] f8 9b [2] e3 d5 [2] de }

  condition:
    any of them
}