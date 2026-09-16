rule TTP_XOR_MULT_DOSStub_8d3a {
  strings:
    $key_8d3a = { d9 52 [2] ad 4a [2] ea 48 [2] ad 59 [2] e3 55 [2] ef 5f [2] f8 54 [2] e3 1a [2] de }

  condition:
    any of them
}