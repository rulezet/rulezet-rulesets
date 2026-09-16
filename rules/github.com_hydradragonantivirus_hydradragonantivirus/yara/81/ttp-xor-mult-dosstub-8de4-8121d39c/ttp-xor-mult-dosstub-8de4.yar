rule TTP_XOR_MULT_DOSStub_8de4 {
  strings:
    $key_8de4 = { d9 8c [2] ad 94 [2] ea 96 [2] ad 87 [2] e3 8b [2] ef 81 [2] f8 8a [2] e3 c4 [2] de }

  condition:
    any of them
}