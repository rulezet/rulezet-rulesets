rule TTP_XOR_MULT_DOSStub_8de5 {
  strings:
    $key_8de5 = { d9 8d [2] ad 95 [2] ea 97 [2] ad 86 [2] e3 8a [2] ef 80 [2] f8 8b [2] e3 c5 [2] de }

  condition:
    any of them
}