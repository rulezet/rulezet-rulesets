rule TTP_XOR_MULT_DOSStub_8dea {
  strings:
    $key_8dea = { d9 82 [2] ad 9a [2] ea 98 [2] ad 89 [2] e3 85 [2] ef 8f [2] f8 84 [2] e3 ca [2] de }

  condition:
    any of them
}