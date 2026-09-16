rule TTP_XOR_MULT_DOSStub_8d7f {
  strings:
    $key_8d7f = { d9 17 [2] ad 0f [2] ea 0d [2] ad 1c [2] e3 10 [2] ef 1a [2] f8 11 [2] e3 5f [2] de }

  condition:
    any of them
}