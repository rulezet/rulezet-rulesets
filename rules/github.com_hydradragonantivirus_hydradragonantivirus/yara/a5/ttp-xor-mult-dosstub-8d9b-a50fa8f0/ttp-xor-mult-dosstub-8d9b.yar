rule TTP_XOR_MULT_DOSStub_8d9b {
  strings:
    $key_8d9b = { d9 f3 [2] ad eb [2] ea e9 [2] ad f8 [2] e3 f4 [2] ef fe [2] f8 f5 [2] e3 bb [2] de }

  condition:
    any of them
}