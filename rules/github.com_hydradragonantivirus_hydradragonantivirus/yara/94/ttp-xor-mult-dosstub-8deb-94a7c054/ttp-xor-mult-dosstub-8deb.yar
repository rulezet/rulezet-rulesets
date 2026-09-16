rule TTP_XOR_MULT_DOSStub_8deb {
  strings:
    $key_8deb = { d9 83 [2] ad 9b [2] ea 99 [2] ad 88 [2] e3 84 [2] ef 8e [2] f8 85 [2] e3 cb [2] de }

  condition:
    any of them
}